package walk

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func paths(files []File) []string {
	out := []string{}
	for _, f := range files {
		out = append(out, f.Path+":"+f.Kind)
	}
	return out
}

func TestCollectsCodeAndConfigOnly(t *testing.T) {
	root := tree(t, map[string]string{
		"composer.json":                  "{}",
		"composer.lock":                  "{}",
		"artisan":                        "<?php",
		"app/Models/User.php":            "<?php",
		"resources/views/x.blade.php":    "x",
		".env":                           "DB_PASSWORD=x",
		".env.production":                "DB_PASSWORD=x",
		".env.example":                   "DB_PASSWORD=",
		"Dockerfile.prod":                "FROM php",
		"docker/nginx/site.conf":         "server {}",
		"vendor/laravel/framework/x.php": "<?php",
		"node_modules/x/index.js":        "x",
		"storage/app/invoice.pdf":        "%PDF",
		"storage/logs/laravel.log":       "secret",
		"public/uploads/a.php":           "<?php",
		"public/images/logo.png":         "png",
		"database/database.sqlite":       "sqlite",
		"database/migrations/2026_x.php": "<?php",
		".github/workflows/ci.yml":       "on: push",
		".git/config":                    "x",
		"auth.json":                      "{}",
	})
	res, err := Walk(root, Defaults)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(paths(res.Files), " ")
	want := ".env:env .env.example:source .env.production:env .github/workflows/ci.yml:source Dockerfile.prod:source app/Models/User.php:source artisan:source composer.json:source composer.lock:source database/migrations/2026_x.php:source docker/nginx/site.conf:source resources/views/x.blade.php:source"
	if got != want {
		t.Errorf("files:\n got %s\nwant %s", got, want)
	}
	excluded := strings.Join(res.ExcludedDirs, " ")
	if excluded != ".git node_modules public/uploads storage vendor" {
		t.Errorf("excluded = %s", excluded)
	}
	if res.NotCollected[".png"] != 1 || res.NotCollected[".sqlite"] != 1 || res.NotCollected[".json"] != 1 {
		t.Errorf("not collected = %v", res.NotCollected)
	}
}

func TestNeverFollowsLinksOrSpecialFiles(t *testing.T) {
	outside := tree(t, map[string]string{"secret.php": "<?php // outside"})
	root := tree(t, map[string]string{"app/a.php": "<?php"})
	if err := os.Symlink(filepath.Join(outside, "secret.php"), filepath.Join(root, "app/link.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "app/pipe.php"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Walk(root, Defaults)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths(res.Files), " "); got != "app/a.php:source" {
		t.Errorf("files = %s", got)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Path] = s.Reason
	}
	if !strings.HasPrefix(reasons["app/link.php"], "symbolic link") || !strings.HasPrefix(reasons["linkdir"], "symbolic link") {
		t.Errorf("links not skipped: %v", reasons)
	}
	if reasons["app/pipe.php"] != "not a regular file" {
		t.Errorf("fifo not skipped: %v", reasons)
	}
}

func TestRootMayBeADeploySymlink(t *testing.T) {
	release := tree(t, map[string]string{"composer.json": "{}"})
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(release, link); err != nil {
		t.Fatal(err)
	}
	res, err := Walk(link, Defaults)
	if err != nil || len(res.Files) != 1 {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestLimits(t *testing.T) {
	root := tree(t, map[string]string{"a.php": "12345", "b.php": "1234567890", "c.php": "123"})
	res, err := Walk(root, Options{MaxFileBytes: 8, MaxTotalBytes: 6, MaxFiles: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(paths(res.Files), " "); got != "a.php:source" {
		t.Errorf("files = %s", got)
	}
	if len(res.Skipped) != 2 {
		t.Errorf("skipped = %v", res.Skipped)
	}
}

func TestReadRefusesASwappedFile(t *testing.T) {
	root := tree(t, map[string]string{"a.php": "<?php", "b.php": "<?php other"})
	res, err := Walk(root, Defaults)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := Read(res.Files[0], 100); err != nil || string(data) != "<?php" {
		t.Fatalf("read = %q, %v", data, err)
	}
	a := filepath.Join(root, "a.php")
	_ = os.Remove(a)
	if err := os.Symlink(filepath.Join(root, "b.php"), a); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(res.Files[0], 100); err == nil {
		t.Fatal("read a file swapped for a link")
	}
}
