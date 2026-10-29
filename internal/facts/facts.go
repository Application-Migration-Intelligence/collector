// Package facts records what the server runs on: OS, PHP and its extensions,
// web server, database, cache and process managers (Amendment 002 §3.1).
//
// It only reads: version commands with fixed arguments and no shell, and a
// short list of configuration files, which are masked for secrets like the
// code. Anything it cannot read is noted and skipped; nothing needs root.
package facts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var versionLine = regexp.MustCompile(`\d+\.\d+`)

// Summary is the line of a command's output that holds its version.
func (c Command) Summary() string {
	for _, line := range strings.Split(c.Output, "\n") {
		if versionLine.MatchString(line) {
			return strings.TrimSpace(line)
		}
	}
	first, _, _ := strings.Cut(c.Output, "\n")
	return first
}

// Command is one version or listing command and what it printed.
type Command struct {
	Args   []string `json:"args"`
	Output string   `json:"output,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// ConfigFile is a server configuration file to include in the package.
type ConfigFile struct {
	Path string `json:"path"` // absolute path on the server
	Size int64  `json:"size"`
}

// Facts is server.json in the package.
type Facts struct {
	OS          map[string]string  `json:"os"`
	Kernel      string             `json:"kernel,omitempty"`
	Arch        string             `json:"arch"`
	CPUs        int                `json:"cpus"`
	MemoryBytes int64              `json:"memory_bytes,omitempty"`
	Commands    map[string]Command `json:"commands"`
	PHPModules  []string           `json:"php_modules,omitempty"`
	PHPIni      map[string]string  `json:"php_ini,omitempty"`
	ConfigFiles []ConfigFile       `json:"config_files"`
	Notes       []string           `json:"notes,omitempty"`
}

// Runner runs a command; replaced in tests.
type Runner func(ctx context.Context, args ...string) (string, error)

// FS reads the server's files; Root is "/" on a real server.
type FS struct {
	Root string
	Run  Runner
}

// System is the real server.
func System() FS { return FS{Root: "/", Run: run} }

const maxOutput = 64 << 10

// Version commands. Each is optional: a missing program is simply absent.
var versionCommands = map[string][]string{
	"php":        {"php", "-v"},
	"composer":   {"composer", "--version", "--no-ansi", "--no-interaction"},
	"node":       {"node", "--version"},
	"npm":        {"npm", "--version"},
	"nginx":      {"nginx", "-v"},
	"apache":     {"apache2", "-v"},
	"httpd":      {"httpd", "-v"},
	"mariadb":    {"mariadb", "--version"},
	"mysql":      {"mysql", "--version"},
	"psql":       {"psql", "--version"},
	"redis":      {"redis-server", "--version"},
	"supervisor": {"supervisord", "--version"},
	"crontab":    {"crontab", "-l"},
}

// PHP settings that matter for an upgrade. Read with `php -r`, never the whole php -i.
var phpIniKeys = []string{
	"memory_limit", "max_execution_time", "upload_max_filesize", "post_max_size",
	"opcache.enable", "opcache.enable_cli", "opcache.jit", "date.timezone",
	"session.save_handler", "error_reporting", "display_errors", "disable_functions",
}

// Server configuration the analysis reads, as glob patterns.
var configGlobs = []string{
	"etc/nginx/nginx.conf", "etc/nginx/sites-enabled/*", "etc/nginx/conf.d/*.conf",
	"etc/apache2/sites-enabled/*", "etc/httpd/conf.d/*.conf",
	"etc/php/*/fpm/pool.d/*.conf", "etc/php-fpm.d/*.conf",
	"etc/supervisor/conf.d/*", "etc/supervisord.d/*",
	"etc/systemd/system/*.service", "etc/systemd/system/*.timer",
	"etc/crontab", "etc/cron.d/*",
}

// Collect gathers the facts. maxConfigBytes bounds each configuration file.
func Collect(ctx context.Context, sys FS, maxConfigBytes int64) Facts {
	f := Facts{
		OS:       readOSRelease(filepath.Join(sys.Root, "etc/os-release")),
		Arch:     runtime.GOARCH,
		CPUs:     runtime.NumCPU(),
		Commands: map[string]Command{},
	}
	if b, err := os.ReadFile(filepath.Join(sys.Root, "proc/sys/kernel/osrelease")); err == nil {
		f.Kernel = strings.TrimSpace(string(b))
	}
	f.MemoryBytes = memTotal(filepath.Join(sys.Root, "proc/meminfo"))

	names := make([]string, 0, len(versionCommands))
	for name := range versionCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args := versionCommands[name]
		out, err := sys.Run(ctx, args...)
		if err != nil && out == "" {
			continue // not installed
		}
		c := Command{Args: args, Output: out}
		if err != nil {
			c.Error = err.Error()
		}
		f.Commands[name] = c
	}

	if _, ok := f.Commands["php"]; ok {
		if out, err := sys.Run(ctx, "php", "-m"); err == nil {
			seen := map[string]bool{}
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "[") && !seen[line] {
					seen[line] = true
					f.PHPModules = append(f.PHPModules, line)
				}
			}
			sort.Strings(f.PHPModules)
		}
		script := `$o=[];foreach(json_decode($argv[1]) as $k){$v=ini_get($k);$o[$k]=$v===false?null:$v;}echo json_encode($o);`
		keys, _ := json.Marshal(phpIniKeys)
		if out, err := sys.Run(ctx, "php", "-n", "-d", "display_errors=0", "-r", script, string(keys)); err == nil {
			_ = json.Unmarshal([]byte(out), &f.PHPIni)
		}
	}

	seen := map[string]bool{}
	for _, pattern := range configGlobs {
		matches, _ := filepath.Glob(filepath.Join(sys.Root, pattern))
		for _, m := range matches {
			st, err := os.Lstat(m)
			if err != nil || !st.Mode().IsRegular() || seen[m] {
				continue // links (sites-enabled is often links) are resolved below
			}
			seen[m] = true
			f.ConfigFiles = appendConfig(f.ConfigFiles, sys.Root, m, st.Size(), maxConfigBytes, &f.Notes)
		}
		// sites-enabled entries are usually links into sites-available: include the target.
		for _, m := range matches {
			st, err := os.Lstat(m)
			if err != nil || st.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := filepath.EvalSymlinks(m)
			if err != nil || !strings.HasPrefix(target, filepath.Join(sys.Root, "etc")+string(os.PathSeparator)) || seen[target] {
				continue
			}
			if tst, err := os.Stat(target); err == nil && tst.Mode().IsRegular() {
				seen[target] = true
				f.ConfigFiles = appendConfig(f.ConfigFiles, sys.Root, target, tst.Size(), maxConfigBytes, &f.Notes)
			}
		}
	}
	sort.Slice(f.ConfigFiles, func(i, j int) bool { return f.ConfigFiles[i].Path < f.ConfigFiles[j].Path })
	return f
}

func appendConfig(list []ConfigFile, root, abs string, size, max int64, notes *[]string) []ConfigFile {
	rel, _ := filepath.Rel(root, abs)
	server := "/" + filepath.ToSlash(rel)
	if size > max {
		*notes = append(*notes, server+": larger than the limit, not included")
		return list
	}
	if fh, err := os.Open(abs); err != nil {
		*notes = append(*notes, server+": not readable without more privileges, not included")
		return list
	} else {
		fh.Close()
	}
	return append(list, ConfigFile{Path: server, Size: size})
}

func readOSRelease(p string) map[string]string {
	out := map[string]string{}
	fh, err := os.Open(p)
	if err != nil {
		return out
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME":
			out[strings.ToLower(k)] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func memTotal(p string) int64 {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0
			}
			return kb * 1024
		}
	}
	return 0
}

// run executes one command with no shell, a short timeout and bounded output.
func run(ctx context.Context, args ...string) (string, error) {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args[1:]...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LC_ALL=C", "COMPOSER_NO_INTERACTION=1"}
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &limited{w: &out, n: maxOutput}
	cmd.Stderr = &limited{w: &out, n: maxOutput} // several tools print versions to stderr
	err = cmd.Run()
	return strings.TrimSpace(out.String()), err
}

type limited struct {
	w *bytes.Buffer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}
