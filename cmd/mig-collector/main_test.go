package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func app(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range map[string]string{
		"composer.json":       `{"require":{"laravel/framework":"^12.0"}}`,
		".env":                "DB_CONNECTION=mariadb\nDB_PASSWORD=hunter2\n",
		"config/database.php": "<?php return ['password' => 'hunter2'];",
	} {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPreviewListsFilesAndSendsNothing(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"preview", "--no-server", app(t)}, &out, &errOut); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	got := out.String()
	for _, want := range []string{"Nothing is sent", "composer.json", ".env  (replaced: driver settings only, 1 other keys left out)", "config/database.php  (1 values masked)"} {
		if !strings.Contains(got, want) {
			t.Errorf("preview missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "hunter2") {
		t.Error("preview printed a secret")
	}
}

func TestPreviewJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"preview", "--json", "--no-server", app(t)}, &out, &errOut); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var doc struct {
		Manifest struct {
			Format string `json:"format"`
			Totals struct {
				Files int `json:"files"`
			} `json:"totals"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Manifest.Format != "mig.collector.package" || doc.Manifest.Totals.Files != 3 {
		t.Fatalf("json = %s (%v)", out.String(), err)
	}
}

func TestCollectWritesAPrivateFileAndNeverOverwrites(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.tar.gz")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"collect", "--no-server", "--out", out, app(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("package file: %v %v", st, err)
	}
	if code := run([]string{"collect", "--no-server", "--out", out, app(t)}, &stdout, &stderr); code != exitError {
		t.Fatalf("overwrote an existing file (exit %d)", code)
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	cases := [][]string{
		{},
		{"nonsense"},
		{"preview", "a", "b"},
		{"preview", t.TempDir()}, // no composer.json
		{"upload", "--endpoint", "https://evil.example", app(t)},
	}
	for _, args := range cases {
		if code := run(args, &out, &errOut); code != exitUsage {
			t.Errorf("run(%v) = %d, want %d", args, code, exitUsage)
		}
	}
	t.Setenv("MIG_COLLECTOR_KEY", "")
	if code := run([]string{"upload", app(t)}, &out, &errOut); code != exitUsage {
		t.Errorf("upload without a key = %d", code)
	}
}
