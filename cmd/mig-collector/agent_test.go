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
	"sync/atomic"
	"testing"
	"time"

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
			State:  filepath.Join(home, ".local", "share", "mig-agent", "state.json"),
		},
		sleep:   func(time.Duration) {},
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

func TestAgentBacksOffAndJitters(t *testing.T) {
	var hits atomic.Int32
	status := http.StatusServiceUnavailable
	_, env, _ := setupAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status != http.StatusNoContent {
			w.Header().Set("Retry-After", "600")
		}
		w.WriteHeader(status)
	}))
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	env.now = func() time.Time { return now }
	var slept []time.Duration
	env.sleep = func(d time.Duration) { slept = append(slept, d) }
	if err := agent.SaveConfig(env.paths.Config, agent.Config{Endpoint: "https://migrateintel.com", Token: testToken, Folder: app(t)}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer

	// A 503 with Retry-After: 10 minutes. The poll fails and records when to try again.
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitError || hits.Load() != 1 {
		t.Fatalf("first poll = %d, hits %d", code, hits.Load())
	}
	if len(slept) != 1 || slept[0] < 0 || slept[0] >= 90*time.Second {
		t.Fatalf("jitter = %v", slept)
	}
	st := agent.LoadState(env.paths.State)
	if st.Failures != 1 || st.NextAfter.Before(now.Add(10*time.Minute)) || st.NextAfter.After(now.Add(13*time.Minute)) {
		t.Fatalf("state = %+v", st)
	}

	// Cron fires again 5 minutes later: the agent waits, without calling MigrateIntel.
	now = now.Add(5 * time.Minute)
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitOK || hits.Load() != 1 {
		t.Fatalf("poll during backoff = %d, hits %d", code, hits.Load())
	}

	// After the wait it asks again; success clears the backoff.
	now = now.Add(10 * time.Minute)
	status = http.StatusNoContent
	if code := run([]string{"agent", "poll"}, &out, &errOut); code != exitOK || hits.Load() != 2 {
		t.Fatalf("poll after backoff = %d, hits %d", code, hits.Load())
	}
	if st := agent.LoadState(env.paths.State); st.Failures != 0 {
		t.Fatalf("state not cleared: %+v", st)
	}

	// --now skips the jitter.
	slept = nil
	_ = run([]string{"agent", "poll", "--now"}, &out, &errOut)
	if len(slept) != 0 {
		t.Fatalf("--now slept %v", slept)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	now := time.Now()
	s := agent.State{}
	for i := 0; i < 10; i++ {
		s = s.Failed(now, 0)
	}
	if wait := s.NextAfter.Sub(now); wait < agent.MaxBackoff || wait > agent.MaxBackoff*6/5+time.Second {
		t.Fatalf("wait after 10 failures = %v", wait)
	}
	if wait := (agent.State{}).Failed(now, 0).NextAfter.Sub(now); wait < 5*time.Minute || wait > 6*time.Minute+time.Second {
		t.Fatalf("first wait = %v", wait)
	}
}

func TestAgentSetToken(t *testing.T) {
	const newToken = "mig_ag_ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfe"
	var seen []string
	_, env, _ := setupAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := agent.SaveConfig(env.paths.Config, agent.Config{Endpoint: "https://migrateintel.com", Token: testToken, Folder: "/var/www/app"}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	t.Setenv("MIG_AGENT_TOKEN", newToken)
	if code := run([]string{"agent", "set-token"}, &out, &errOut); code != exitOK {
		t.Fatalf("set-token = %d: %s", code, errOut.String())
	}
	cfg, err := agent.LoadConfig(env.paths.Config)
	if err != nil || cfg.Token != newToken || cfg.Folder != "/var/www/app" {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	if len(seen) != 1 || seen[0] != "Bearer "+newToken {
		t.Fatalf("checked in with %v", seen)
	}
	t.Setenv("MIG_AGENT_TOKEN", "nonsense")
	if code := run([]string{"agent", "set-token"}, &out, &errOut); code != exitUsage {
		t.Errorf("bad token = %d", code)
	}
}
