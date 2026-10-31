package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Application-Migration-Intelligence/collector/internal/facts"
	"github.com/Application-Migration-Intelligence/collector/internal/walk"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func unpack(t *testing.T, data []byte) (names []string, files map[string]string) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files = map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		names = append(names, h.Name)
		files[h.Name] = string(b)
	}
	return names, files
}

func build(t *testing.T) (string, string) {
	t.Helper()
	app := t.TempDir()
	write(t, app, "composer.json", `{"require": {"php": "^8.2"}}`)
	write(t, app, "config/services.php", "<?php return ['stripe' => ['secret' => 'sk_live_abcdefghijklmnop1234']];")
	write(t, app, ".env", "APP_KEY=base64:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nDB_CONNECTION=mysql\nDB_PASSWORD=hunter2\n")
	write(t, app, "resources/js/bin.js", "abc\x00def")
	sys := t.TempDir()
	write(t, sys, "etc/nginx/conf.d/app.conf", "server { fastcgi_param DB_PASSWORD hunter2; }")
	return app, sys
}

func TestWrite(t *testing.T) {
	app, sys := build(t)
	res, err := walk.Walk(app, walk.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	f := facts.Facts{
		OS:          map[string]string{"id": "ubuntu"},
		Commands:    map[string]facts.Command{"crontab": {Args: []string{"crontab", "-l"}, Output: "* * * * * curl https://x/?token=1 API_TOKEN=abc123"}},
		ConfigFiles: []facts.ConfigFile{{Path: "/etc/nginx/conf.d/app.conf", Size: 10}},
	}
	var buf bytes.Buffer
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	m, err := Write(context.Background(), &buf, res, &f, Options{Version: "1.0.0", Now: now, SysRoot: sys, MaxConfigBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}

	names, files := unpack(t, buf.Bytes())
	if names[len(names)-1] != "manifest.json" {
		t.Errorf("manifest is not last: %v", names)
	}
	all := strings.Join(names, " ")
	for _, want := range []string{"source/.env", "source/composer.json", "source/config/services.php", "server/files/etc/nginx/conf.d/app.conf", "server.json"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %s in %v", want, names)
		}
	}
	if strings.Contains(all, "bin.js") {
		t.Error("binary file was packaged")
	}

	blob := strings.Join([]string{files["source/.env"], files["source/config/services.php"], files["server/files/etc/nginx/conf.d/app.conf"], files["server.json"], files["manifest.json"]}, "\n")
	for _, secret := range []string{"hunter2", "sk_live_", "aaaaaaaaaaaaaaaa", "abc123"} {
		if strings.Contains(blob, secret) {
			t.Errorf("secret %q left the server", secret)
		}
	}
	if !strings.Contains(files["source/.env"], "DB_CONNECTION=mysql") {
		t.Errorf(".env lost its driver settings: %q", files["source/.env"])
	}

	var back Manifest
	if err := json.Unmarshal([]byte(files["manifest.json"]), &back); err != nil {
		t.Fatal(err)
	}
	if back.Format != Format || back.Totals.Files != 3 || back.Totals.ServerFiles != 1 || back.Totals.EnvKeysDropped != 2 || back.Totals.Redactions < 2 {
		t.Errorf("manifest = %+v", back.Totals)
	}
	if m.CreatedAt != "2026-10-29T12:00:00Z" {
		t.Errorf("created_at = %s", m.CreatedAt)
	}
	found := false
	for _, s := range back.Skipped {
		if s.Path == "resources/js/bin.js" && s.Reason == "binary file" {
			found = true
		}
	}
	if !found {
		t.Errorf("binary file not listed as skipped: %v", back.Skipped)
	}

	// The same input gives the same bytes.
	var again bytes.Buffer
	if _, err := Write(context.Background(), &again, res, &f, Options{Version: "1.0.0", Now: now, SysRoot: sys, MaxConfigBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Error("package is not deterministic")
	}
}

// Regression: the contents of key, certificate, credential and data files are
// never collected, wherever they sit in the application folder.
func TestSensitiveFileContentsAreNeverCollected(t *testing.T) {
	app := t.TempDir()
	const marker = "SENSITIVE-CONTENT-7f3a"
	write(t, app, "composer.json", `{"require": {"php": "^8.2"}}`)
	for _, rel := range []string{
		"private.key", "request.csr", "server.pem", "cert.crt", "keystore.p12", "id_rsa", "id_ed25519",
		"auth.json", "database/database.sqlite", "dump.sql", "backup.sql.gz", "storage/oauth-private.key",
		"uploads/passport.pdf", "public/uploads/id.jpg", ".htpasswd", "credentials.json.bak", ".npmrc",
	} {
		write(t, app, rel, marker)
	}
	res, err := walk.Walk(app, walk.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := Write(context.Background(), &buf, res, nil, Options{Version: "test", Now: time.Unix(0, 0), MaxConfigBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	names, files := unpack(t, buf.Bytes())
	for name, content := range files {
		if strings.Contains(content, marker) {
			t.Errorf("%s holds the contents of a sensitive file", name)
		}
	}
	if len(names) == 0 {
		t.Fatal("empty package")
	}
}
