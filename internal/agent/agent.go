// Package agent is the collector's opt-in agent mode (MigrateIntel Amendment
// 005, method 3). The agent only makes outbound HTTPS requests to
// MigrateIntel: every few minutes cron runs "mig-collector agent poll", which
// asks whether a scan was requested from the project page and, if so, runs
// the same collection and upload as the one-time command. MigrateIntel never
// connects to the server and holds no credential for it. No root is needed:
// the agent lives in the user's home folder and crontab.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// TokenPrefix starts every agent token.
const TokenPrefix = "mig_ag_"

// CronMarker tags the agent's crontab line so it can be found and removed.
const CronMarker = "# mig-agent"

// Schedule is how often cron runs the agent.
const Schedule = "*/5 * * * *"

var tokenFormat = regexp.MustCompile(`^mig_ag_[A-Za-z0-9]{48}$`)
var requestID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Config is what install saves, readable only by the user.
type Config struct {
	Endpoint string `json:"endpoint"` // https://<MigrateIntel host>
	Token    string `json:"token"`
	Folder   string `json:"folder"`
	NoServer bool   `json:"no_server,omitempty"`
}

// CheckToken validates an agent token's shape (MigrateIntel checks it for real).
func CheckToken(token string) error {
	if !tokenFormat.MatchString(token) {
		return errors.New("the agent token is missing or malformed; copy the install command again from your project page")
	}
	return nil
}

// Paths are where the agent keeps its files.
type Paths struct {
	Config string // ~/.config/mig-agent/agent.json
	Binary string // ~/.local/share/mig-agent/mig-collector
	Lock   string // ~/.local/share/mig-agent/poll.lock
}

// DefaultPaths uses XDG locations under the user's home folder.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(home, ".local", "share")
	}
	return Paths{
		Config: filepath.Join(cfg, "mig-agent", "agent.json"),
		Binary: filepath.Join(data, "mig-agent", "mig-collector"),
		Lock:   filepath.Join(data, "mig-agent", "poll.lock"),
	}, nil
}

// SaveConfig writes the config with 0600 permissions in a 0700 folder.
func SaveConfig(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadConfig reads the config, refusing one that others can read.
func LoadConfig(path string) (Config, error) {
	var c Config
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, errors.New("the agent is not installed for this user (run the install command from your project page)")
		}
		return c, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return c, fmt.Errorf("%s must be a regular file readable only by you (chmod 600)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s is damaged: %w", path, err)
	}
	return c, CheckToken(c.Token)
}

// InstallBinary copies the running collector to a stable place for cron.
func InstallBinary(self, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// Crontab reads and writes the user's crontab.
type Crontab interface {
	Read(ctx context.Context) (string, error)
	Write(ctx context.Context, content string) error
}

// SystemCrontab uses the crontab command.
type SystemCrontab struct{}

func (SystemCrontab) Read(ctx context.Context) (string, error) {
	path, err := exec.LookPath("crontab")
	if err != nil {
		return "", errors.New("the crontab command is not available; install cron, or use the one-time command instead")
	}
	out, err := exec.CommandContext(ctx, path, "-l").CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %s", strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (SystemCrontab) Write(ctx context.Context, content string) error {
	path, err := exec.LookPath("crontab")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, "-")
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("crontab -: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CronLine is the agent's crontab entry.
func CronLine(binary string) string {
	return fmt.Sprintf("%s %s agent poll >/dev/null 2>&1 %s", Schedule, shellQuote(binary), CronMarker)
}

// WithAgentLine returns the crontab with exactly one agent line (or none, when line is "").
func WithAgentLine(crontab, line string) string {
	var kept []string
	for _, l := range strings.Split(strings.TrimRight(crontab, "\n"), "\n") {
		if l == "" && len(kept) == 0 {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(l), CronMarker) {
			continue
		}
		kept = append(kept, l)
	}
	if line != "" {
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
}

func shellQuote(s string) string {
	if regexp.MustCompile(`^[A-Za-z0-9_/.\-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Client talks to the agent API with the agent's token.
type Client struct {
	HTTP      *http.Client
	Endpoint  string // https://<host>, already checked
	Token     string
	UserAgent string
}

// Poll asks for a scan request. It returns "" when there is none.
func (c *Client) Poll(ctx context.Context) (string, error) {
	resp, body, err := c.post(ctx, "/api/agent/v1/poll", nil, "")
	if err != nil {
		return "", err
	}
	switch resp.StatusCode {
	case http.StatusNoContent:
		return "", nil
	case http.StatusOK:
		var r struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(body, &r); err != nil || !requestID.MatchString(r.RequestID) {
			return "", errors.New("unexpected reply from MigrateIntel")
		}
		return r.RequestID, nil
	}
	return "", problem(resp, body)
}

// UploadPath is where the package for a request goes. The agent builds it
// itself from the request ID; it never follows a URL from the reply.
func UploadPath(id string) string {
	return "/api/agent/v1/requests/" + id + "/package"
}

// Failed reports that a claimed request could not be collected.
func (c *Client) Failed(ctx context.Context, id, message string) error {
	if !requestID.MatchString(id) {
		return errors.New("bad request id")
	}
	payload, _ := json.Marshal(map[string]string{"message": truncate(message, 300)})
	resp, body, err := c.post(ctx, "/api/agent/v1/requests/"+id+"/failed", bytes.NewReader(payload), "application/json")
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return problem(resp, body)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, body io.Reader, contentType string) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp, data, nil
}

func problem(resp *http.Response, body []byte) error {
	var p struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	_ = json.Unmarshal(body, &p)
	if p.Message == "" {
		p.Message = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("MigrateIntel refused (%d %s): %s", resp.StatusCode, p.Code, p.Message)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Lock makes sure only one poll runs at a time. A lock older than an hour is stale.
func Lock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		st, serr := os.Stat(path)
		if serr == nil && time.Since(st.ModTime()) > time.Hour {
			_ = os.Remove(path)
			continue
		}
		return nil, errors.New("another agent run is still in progress")
	}
	return nil, errors.New("could not take the agent lock")
}
