package facts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollect(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nHOME_URL=x\n")
	write(t, root, "proc/meminfo", "MemTotal:        8000000 kB\nMemFree: 1 kB\n")
	write(t, root, "etc/php/8.3/fpm/pool.d/www.conf", "listen = /run/php/php8.3-fpm.sock\n")
	avail := write(t, root, "etc/nginx/sites-available/app", "server { root /var/www/app/public; }\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(avail, filepath.Join(root, "etc/nginx/sites-enabled/app")); err != nil {
		t.Fatal(err)
	}
	// A link that points outside /etc is not followed.
	outside := write(t, root, "home/user/secret.conf", "x")
	if err := os.Symlink(outside, filepath.Join(root, "etc/nginx/sites-enabled/evil")); err != nil {
		t.Fatal(err)
	}

	runner := func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "php -v":
			return "PHP 8.3.6 (cli)", nil
		case "php -m":
			return "[PHP Modules]\nmbstring\nCore\npdo_mysql\n\n[Zend Modules]\n", nil
		case "nginx -v":
			return "nginx version: nginx/1.24.0", nil
		case "crontab -l":
			return "no crontab for www", errors.New("exit status 1")
		}
		if args[0] == "php" && args[1] == "-n" {
			t.Errorf("php -n reads built-in defaults, not the server's php.ini")
		}
		if args[0] == "php" && args[1] == "-d" && args[2] == "display_errors=0" {
			return `{"memory_limit":"512M","date.timezone":"UTC"}`, nil
		}
		return "", errors.New("not found")
	}

	f := Collect(context.Background(), FS{Root: root, Run: runner}, 1<<20)

	if f.OS["id"] != "ubuntu" || f.OS["version_id"] != "24.04" || f.OS["home_url"] != "" {
		t.Errorf("os = %v", f.OS)
	}
	if f.MemoryBytes != 8000000*1024 {
		t.Errorf("memory = %d", f.MemoryBytes)
	}
	if f.Commands["php"].Output != "PHP 8.3.6 (cli)" || f.Commands["nginx"].Output == "" {
		t.Errorf("commands = %v", f.Commands)
	}
	if _, ok := f.Commands["mysql"]; ok {
		t.Error("a missing program was recorded")
	}
	if f.Commands["crontab"].Error == "" {
		t.Error("a command that failed with output keeps its error")
	}
	if strings.Join(f.PHPModules, ",") != "Core,mbstring,pdo_mysql" {
		t.Errorf("modules = %v", f.PHPModules)
	}
	if f.PHPIni["memory_limit"] != "512M" {
		t.Errorf("ini = %v", f.PHPIni)
	}
	var paths []string
	for _, c := range f.ConfigFiles {
		paths = append(paths, c.Path)
	}
	if got := strings.Join(paths, " "); got != "/etc/nginx/sites-available/app /etc/php/8.3/fpm/pool.d/www.conf" {
		t.Errorf("config files = %s", got)
	}
}
