// mig-collector reads a PHP application and its server, and sends what the
// MigrateIntel analysis needs to the customer's project, once. It never
// changes the application, needs no admin rights and talks only to
// MigrateIntel. Licensed under the Apache License 2.0.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Application-Migration-Intelligence/collector/internal/facts"
	"github.com/Application-Migration-Intelligence/collector/internal/pack"
	"github.com/Application-Migration-Intelligence/collector/internal/upload"
	"github.com/Application-Migration-Intelligence/collector/internal/walk"
)

// Set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2

	maxConfigBytes = 1 << 20
)

const usage = `MigrateIntel collector %s

Usage:
  mig-collector preview [--json] [--no-server] [FOLDER]
      List exactly what would be read and sent. Nothing leaves the server.
  mig-collector collect [--out FILE] [--no-server] [FOLDER]
      Write the package to a file on this server. You decide whether to upload it.
  mig-collector upload [--endpoint URL] [--no-server] [FOLDER]
      Collect and send to your MigrateIntel project. The one-time project key is
      read from the MIG_COLLECTOR_KEY environment variable, or from standard
      input with --key-stdin.
  mig-collector agent install [--endpoint URL] [--no-server] FOLDER
      Opt-in agent: lets you start scans from your project page. Every 5 minutes
      it asks MigrateIntel (outbound only) whether a scan was requested. The
      token is read from MIG_AGENT_TOKEN. No root needed: it uses your crontab.
  mig-collector agent status | agent poll | agent remove
  mig-collector version

FOLDER is the application folder (the one with composer.json); the default is
the current folder. --no-server leaves out the server facts and configuration.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	if cmd == "agent" {
		return runAgent(ctx, rest, stdout, stderr)
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "preview as JSON")
	noServer := fs.Bool("no-server", false, "leave out server facts and configuration")
	out := fs.String("out", "", "package file to write (collect)")
	endpoint := fs.String("endpoint", upload.DefaultEndpoint, "MigrateIntel address (upload)")
	keyStdin := fs.Bool("key-stdin", false, "read the project key from standard input (upload)")

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "mig-collector %s\n", version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, usage, version)
		return exitOK
	case "preview", "collect", "upload":
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n"+usage, cmd, version)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "give one application folder")
		return exitUsage
	}
	folder := "."
	if fs.NArg() == 1 {
		folder = fs.Arg(0)
	}

	var err error
	switch cmd {
	case "preview":
		err = preview(ctx, stdout, folder, !*noServer, *asJSON)
	case "collect":
		err = collect(ctx, stdout, folder, !*noServer, *out)
	case "upload":
		err = send(ctx, stdout, folder, !*noServer, *endpoint, *keyStdin)
	}
	if err != nil {
		fmt.Fprintln(stderr, "mig-collector:", err)
		if errors.Is(err, errUsage) {
			return exitUsage
		}
		return exitError
	}
	return exitOK
}

var errUsage = errors.New("usage")

type plan struct {
	res   *walk.Result
	facts *facts.Facts
}

func gather(ctx context.Context, folder string, server bool) (*plan, error) {
	abs, err := filepath.Abs(folder)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(abs, "/path/to") {
		return nil, fmt.Errorf("%w: %s is the example from the instructions; give your application's folder, the one that holds composer.json (for example /var/www/yourapp)", errUsage, folder)
	}
	if st, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("%w: the folder %s does not exist; give your application's folder, the one that holds composer.json (for example /var/www/yourapp)", errUsage, abs)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("%w: %s is a file; give your application's folder, the one that holds composer.json", errUsage, abs)
	}
	res, err := walk.Walk(abs, walk.Defaults)
	if err != nil {
		return nil, err
	}
	p := &plan{res: res}
	if !hasComposer(res) {
		if sub := composerBelow(abs); sub != "" {
			return nil, fmt.Errorf("%w: %s has no composer.json, but %s does; give that folder", errUsage, abs, sub)
		}
		return nil, fmt.Errorf("%w: %s has no composer.json; give your application's folder, the one that holds composer.json", errUsage, abs)
	}
	if server {
		f := facts.Collect(ctx, facts.System(), maxConfigBytes)
		p.facts = &f
	}
	return p, nil
}

// composerBelow names a direct subfolder that holds composer.json, if one does.
func composerBelow(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		candidate := filepath.Join(dir, e.Name())
		if st, err := os.Lstat(filepath.Join(candidate, "composer.json")); err == nil && st.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func hasComposer(res *walk.Result) bool {
	for _, f := range res.Files {
		if f.Path == "composer.json" {
			return true
		}
	}
	return false
}

func write(ctx context.Context, w io.Writer, p *plan) (*pack.Manifest, error) {
	return pack.Write(ctx, w, p.res, p.facts, pack.Options{
		Version: version, Now: time.Now(), SysRoot: "/", MaxConfigBytes: maxConfigBytes,
	})
}

func preview(ctx context.Context, stdout io.Writer, folder string, server, asJSON bool) error {
	p, err := gather(ctx, folder, server)
	if err != nil {
		return err
	}
	m, err := write(ctx, io.Discard, p)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Manifest *pack.Manifest `json:"manifest"`
			Server   *facts.Facts   `json:"server,omitempty"`
		}{m, p.facts})
	}

	fmt.Fprintf(stdout, "MigrateIntel collector %s: preview. Nothing is sent.\n\n", version)
	fmt.Fprintf(stdout, "Application folder: %s\n", p.res.Root)
	fmt.Fprintf(stdout, "Would send %d files (%s), with %d secret values masked.\n\n", m.Totals.Files, size(m.Totals.Bytes), m.Totals.Redactions)
	for _, e := range m.Files {
		note := ""
		switch {
		case e.Kind == walk.KindEnv:
			note = fmt.Sprintf("  (replaced: driver settings only, %d other keys left out)", e.Dropped)
		case e.Redactions > 0:
			note = fmt.Sprintf("  (%d values masked)", e.Redactions)
		}
		fmt.Fprintf(stdout, "  %s%s\n", e.Path, note)
	}
	if len(m.ExcludedDirs) > 0 {
		fmt.Fprintf(stdout, "\nFolders not read: %s\n", strings.Join(m.ExcludedDirs, ", "))
	}
	if len(m.NotCollected) > 0 {
		var parts []string
		for ext, n := range m.NotCollected {
			parts = append(parts, fmt.Sprintf("%s %d", ext, n))
		}
		sort.Strings(parts)
		fmt.Fprintf(stdout, "Other files not read (not used by the analysis): %s\n", strings.Join(parts, ", "))
	}
	if len(m.Skipped) > 0 {
		fmt.Fprintln(stdout, "\nSkipped:")
		for _, s := range m.Skipped {
			fmt.Fprintf(stdout, "  %s: %s\n", s.Path, s.Reason)
		}
	}
	if p.facts != nil {
		fmt.Fprintln(stdout, "\nServer facts:")
		if v := p.facts.OS["pretty_name"]; v != "" {
			fmt.Fprintf(stdout, "  OS: %s (%s)\n", v, p.facts.Arch)
		}
		names := make([]string, 0, len(p.facts.Commands))
		for name := range p.facts.Commands {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			first := p.facts.Commands[name].Summary()
			if name == "crontab" {
				first = "(the current user's crontab, secrets masked)"
			}
			fmt.Fprintf(stdout, "  %s: %s\n", name, first)
		}
		if len(p.facts.PHPModules) > 0 {
			fmt.Fprintf(stdout, "  PHP extensions: %s\n", strings.Join(p.facts.PHPModules, ", "))
		}
		for _, e := range m.ServerFiles {
			fmt.Fprintf(stdout, "  config: %s (%d values masked)\n", e.Path, e.Redactions)
		}
		for _, n := range p.facts.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", n)
		}
	}
	fmt.Fprintln(stdout, "\nTo write the package here: mig-collector collect. To send it: mig-collector upload.")
	return nil
}

func collect(ctx context.Context, stdout io.Writer, folder string, server bool, out string) error {
	p, err := gather(ctx, folder, server)
	if err != nil {
		return err
	}
	if out == "" {
		out = fmt.Sprintf("mig-package-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}
	fh, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	m, err := write(ctx, fh, p)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s: %d files, %d server configuration files, %d secret values masked.\n", out, m.Totals.Files, m.Totals.ServerFiles, m.Totals.Redactions)
	fmt.Fprintln(stdout, "Upload it from your project page, or delete it when you are done.")
	return nil
}

func send(ctx context.Context, stdout io.Writer, folder string, server bool, endpoint string, keyStdin bool) error {
	intake, err := upload.CheckEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	key := strings.TrimSpace(os.Getenv("MIG_COLLECTOR_KEY"))
	if keyStdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 512))
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(b))
	}
	if err := upload.CheckKey(key); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}

	p, err := gather(ctx, folder, server)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "mig-collector-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	file := filepath.Join(dir, "package.tar.gz")
	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	m, err := write(ctx, fh, p)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Sending %d files and the server facts (%d secret values masked)...\n", m.Totals.Files, m.Totals.Redactions)
	res, err := upload.New(version).Send(ctx, intake, key, file)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Sent. Package %s. Follow the analysis at %s\n", res.PackageID, res.ProjectURL)
	return nil
}

func size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
