package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Application-Migration-Intelligence/collector/internal/agent"
)

type fakeCrontab struct{ content string }

func (f *fakeCrontab) Read(context.Context) (string, error)    { return f.content, nil }
func (f *fakeCrontab) Write(_ context.Context, c string) error { f.content = c; return nil }

const testToken = "mig_ag_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
const testRequest = "0b9e5a52-6c1f-4d2e-9a3b-1c2d3e4f5a6b"

func setupAgent(t *testing.T, handler http.Handler) (*fakeCrontab, *agentEnv, *[]string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	home := t.TempDir()
	cron := &fakeCrontab{content: "0 3 * * * /usr/bin/backup\n"}
	self := filepath.Join(home, "self-binary")
	_ = os.WriteFile(self, []byte("binary"), 0o700)
	var mu sync.Mutex
	sent := []string{}
	env := &agentEnv{
		paths: &agent.Paths{
			Config: filepath.Join(home, ".config", "mig-agent", "agent.json"),
			Binary: filepath.Join(home, ".local", "share", "mig-agent", "mig-collector"),
			Lock:   filepath.Join(home, ".local", "share", "mig-agent", "poll.lock"),
		},
		crontab: cron,
		self:    self,
		client: func(_ string, token string) *agent.Client {
			return &agent.Client{HTTP: srv.Client(), Endpoint: srv.URL, Token: token, UserAgent: "test"}
		},
		sender: func(_ context.Context, url, token, file string) error {
			mu.Lock()
			defer mu.Unlock()
			st, err := os.Stat(file)
			if err != nil || st.Size() == 0 {
				t.Errorf("no package written")
			}
			sent = append(sent, url+" "+token)
			return nil
		},
	}
	testAgentEnv = env
	t.Cleanup(func() { testAgentEnv = nil })
	return cron, env, &sent
}

func TestAgentInstallPollRemove(t *testing.T) {
	requested := true
	var failed []string
	cron, env, sent := setupAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/agent/v1/poll":
			if !requested {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			requested = false
			_ = json.NewEncoder(w).Encode(map[string]string{"request_id": testRequest, "upload_url": "https://evil.example/steal"})
		case "/api/agent/v1/requests/" + testRequest + "/failed":
			failed = append(failed, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	appDir := app(t)

	var out, errOut bytes.Buffer
	t.Setenv("MIG_AGENT_TOKEN", testToken)
	requested = false
	if code := run([]string{"agent", "install", appDir}, &out, &errOut); code != exitOK {
		t.Fatalf("install = %d: %s", code, errOut.String())
	}
	st, err := os.Stat(env.paths.Config)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config not private: %v %v", st, err)
	}
	if !strings.Contains(cron.content, "/usr/bin/backup") || strings.Count(cron.content, agent.CronMarker) != 1 {
		t.Fatalf("crontab = %q", cron.content)
	}
	// Installing again keeps one line.
	_ = run([]string{"agent", "install", appDir}, &out, &errOut)
	if strings.Count(cron.content, agent.CronMarker) != 1 {
		t.Fatalf("crontab after reinstall = %q", cron.content)
	}

	// A requested scan is collected and sent to the path built from the ID,
	// never to the URL in the reply.
	requested = true
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitOK {
		t.Fatalf("poll = %d: %s", code, errOut.String())
	}
	if len(*sent) != 1 || !strings.HasSuffix(strings.Fields((*sent)[0])[0], "/api/agent/v1/requests/"+testRequest+"/package") || strings.Contains((*sent)[0], "evil") {
		t.Fatalf("sent = %v", *sent)
	}
	// Nothing requested: nothing sent.
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitOK || len(*sent) != 1 {
		t.Fatalf("idle poll = %d, sent %v", code, *sent)
	}

	// A failing collection is reported.
	_ = os.Remove(filepath.Join(appDir, "composer.json"))
	requested = true
	if code := run([]string{"agent", "poll"}, &out, &errOut); code == exitOK || len(failed) != 1 {
		t.Fatalf("failing poll = %d, failed %v", code, failed)
	}

	if code := run([]string{"agent", "remove"}, &out, &errOut); code != exitOK {
		t.Fatalf("remove = %d: %s", code, errOut.String())
	}
	if strings.Contains(cron.content, agent.CronMarker) || !strings.Contains(cron.content, "/usr/bin/backup") {
		t.Fatalf("crontab after remove = %q", cron.content)
	}
	for _, p := range []string{env.paths.Config, env.paths.Binary} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", p)
		}
	}
}

func TestAgentRefusals(t *testing.T) {
	setupAgent(t, http.NotFoundHandler())
	var out, errOut bytes.Buffer
	t.Setenv("MIG_AGENT_TOKEN", "mig_ck_not-an-agent-token-at-all-000000")
	if code := run([]string{"agent", "install", app(t)}, &out, &errOut); code != exitUsage {
		t.Errorf("bad token = %d", code)
	}
	t.Setenv("MIG_AGENT_TOKEN", testToken)
	if code := run([]string{"agent", "install", "--endpoint", "https://evil.example", app(t)}, &out, &errOut); code != exitUsage {
		t.Errorf("foreign endpoint = %d", code)
	}
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitError || !strings.Contains(errOut.String(), "not installed") {
		t.Errorf("poll without install = %d: %s", code, errOut.String())
	}
}

func TestCrontabLine(t *testing.T) {
	line := agent.CronLine("/home/deploy/.local/share/mig-agent/mig-collector")
	if line != "*/5 * * * * /home/deploy/.local/share/mig-agent/mig-collector agent poll >/dev/null 2>&1 # mig-agent" {
		t.Errorf("line = %q", line)
	}
	if got := agent.CronLine("/home/a b/x"); !strings.Contains(got, "'/home/a b/x'") {
		t.Errorf("quoted = %q", got)
	}
	if got := agent.WithAgentLine("", ""); got != "" {
		t.Errorf("empty = %q", got)
	}
}
