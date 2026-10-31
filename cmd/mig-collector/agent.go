package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Application-Migration-Intelligence/collector/internal/agent"
	"github.com/Application-Migration-Intelligence/collector/internal/upload"
)

// agentEnv lets tests point the agent at temporary paths, a fake crontab and
// a test server. In normal use every field is nil and the real ones are used.
type agentEnv struct {
	paths   *agent.Paths
	crontab agent.Crontab
	self    string
	client  func(endpoint, token string) *agent.Client
	sender  func(ctx context.Context, url, token, file string) error
}

var testAgentEnv *agentEnv

func runAgent(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, version)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("agent "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("endpoint", upload.DefaultEndpoint, "MigrateIntel address")
	noServer := fs.Bool("no-server", false, "leave out server facts and configuration")
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}

	var err error
	switch sub {
	case "install":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "give the application folder: mig-collector agent install /var/www/your-app")
			return exitUsage
		}
		err = agentInstall(ctx, stdout, fs.Arg(0), *endpoint, *noServer)
	case "poll":
		err = agentPoll(ctx, stdout)
	case "status":
		err = agentStatus(ctx, stdout)
	case "remove":
		err = agentRemove(ctx, stdout)
	default:
		fmt.Fprintf(stderr, "unknown agent command %q\n\n"+usage, sub, version)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "mig-collector agent:", err)
		if errors.Is(err, errUsage) {
			return exitUsage
		}
		return exitError
	}
	return exitOK
}

func agentSetup() (agent.Paths, agent.Crontab, error) {
	if testAgentEnv != nil {
		return *testAgentEnv.paths, testAgentEnv.crontab, nil
	}
	p, err := agent.DefaultPaths()
	return p, agent.SystemCrontab{}, err
}

func agentClient(endpoint, token string) *agent.Client {
	if testAgentEnv != nil && testAgentEnv.client != nil {
		return testAgentEnv.client(endpoint, token)
	}
	c := upload.New(version)
	return &agent.Client{HTTP: c.HTTP, Endpoint: endpoint, Token: token, UserAgent: c.UserAgent}
}

func agentInstall(ctx context.Context, stdout io.Writer, folder, endpoint string, noServer bool) error {
	base, err := upload.BaseURL(endpoint)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	token := strings.TrimSpace(os.Getenv("MIG_AGENT_TOKEN"))
	if err := agent.CheckToken(token); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if os.Geteuid() == 0 && testAgentEnv == nil {
		return fmt.Errorf("%w: run the agent as the user that can read the application, not root", errUsage)
	}
	// The folder must be an application folder now, not at the first scan.
	if _, err := gather(ctx, folder, false); err != nil {
		return err
	}
	abs, _ := filepath.Abs(folder)

	paths, crontab, err := agentSetup()
	if err != nil {
		return err
	}
	self := ""
	if testAgentEnv != nil {
		self = testAgentEnv.self
	} else if self, err = os.Executable(); err != nil {
		return err
	}
	if err := agent.InstallBinary(self, paths.Binary); err != nil {
		return fmt.Errorf("installing the agent: %w", err)
	}
	if err := agent.SaveConfig(paths.Config, agent.Config{Endpoint: base, Token: token, Folder: abs, NoServer: noServer}); err != nil {
		return err
	}
	current, err := crontab.Read(ctx)
	if err != nil {
		return err
	}
	if err := crontab.Write(ctx, agent.WithAgentLine(current, agent.CronLine(paths.Binary))); err != nil {
		return err
	}

	// Check in once now, so the project page shows the agent straight away.
	if _, err := agentClient(base, token).Poll(ctx); err != nil {
		return fmt.Errorf("installed, but MigrateIntel could not be reached: %w", err)
	}
	fmt.Fprintf(stdout, "Agent installed for %s. It checks in every 5 minutes; start a scan from your project page.\n", abs)
	fmt.Fprintln(stdout, "To remove it: mig-collector agent remove (or remove it on your project page).")
	return nil
}

func agentPoll(ctx context.Context, stdout io.Writer) error {
	paths, _, err := agentSetup()
	if err != nil {
		return err
	}
	unlock, err := agent.Lock(paths.Lock)
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := agent.LoadConfig(paths.Config)
	if err != nil {
		return err
	}
	base, err := upload.BaseURL(cfg.Endpoint)
	if err != nil {
		return err
	}
	client := agentClient(base, cfg.Token)
	id, err := client.Poll(ctx)
	if err != nil || id == "" {
		return err
	}

	fmt.Fprintf(stdout, "Scan %s requested: collecting %s\n", id, cfg.Folder)
	if err := agentScan(ctx, stdout, cfg, base+agent.UploadPath(id)); err != nil {
		_ = client.Failed(ctx, id, err.Error())
		return err
	}
	return nil
}

func agentScan(ctx context.Context, stdout io.Writer, cfg agent.Config, url string) error {
	p, err := gather(ctx, cfg.Folder, !cfg.NoServer)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "mig-agent-")
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
	if testAgentEnv != nil && testAgentEnv.sender != nil {
		err = testAgentEnv.sender(ctx, url, cfg.Token, file)
	} else {
		_, err = upload.New(version).Send(ctx, url, cfg.Token, file)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Sent %d files (%d secret values masked).\n", m.Totals.Files, m.Totals.Redactions)
	return nil
}

func agentStatus(ctx context.Context, stdout io.Writer) error {
	paths, crontab, err := agentSetup()
	if err != nil {
		return err
	}
	cfg, err := agent.LoadConfig(paths.Config)
	if err != nil {
		return err
	}
	current, err := crontab.Read(ctx)
	if err != nil {
		return err
	}
	scheduled := strings.Contains(current, agent.CronMarker)
	fmt.Fprintf(stdout, "Agent for %s, reporting to %s, token %s…\n", cfg.Folder, cfg.Endpoint, cfg.Token[:12])
	if scheduled {
		fmt.Fprintln(stdout, "Scheduled: every 5 minutes (crontab).")
	} else {
		fmt.Fprintln(stdout, "Not scheduled: the crontab line is missing. Install again, or remove.")
	}
	return nil
}

func agentRemove(ctx context.Context, stdout io.Writer) error {
	paths, crontab, err := agentSetup()
	if err != nil {
		return err
	}
	current, err := crontab.Read(ctx)
	if err != nil {
		return err
	}
	if strings.Contains(current, agent.CronMarker) {
		if err := crontab.Write(ctx, agent.WithAgentLine(current, "")); err != nil {
			return err
		}
	}
	for _, p := range []string{paths.Config, paths.Binary, paths.Lock} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = os.Remove(filepath.Dir(paths.Config))
	_ = os.Remove(filepath.Dir(paths.Binary))
	fmt.Fprintln(stdout, "Agent removed: the crontab line, its token and its copy of the collector are deleted.")
	return nil
}
