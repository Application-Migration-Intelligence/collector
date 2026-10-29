package envfile

import (
	"strings"
	"testing"
)

func TestFilterKeepsOnlyDriverSettings(t *testing.T) {
	in := `APP_NAME="Acme"
APP_KEY=base64:secretsecretsecret
APP_ENV=production
DB_CONNECTION=mariadb
DB_PASSWORD=hunter2
export QUEUE_CONNECTION="redis" # workers
CACHE_STORE=null
MAIL_MAILER=smtp://user:pass@host
`
	out, dropped := Filter([]byte(in))
	got := string(out)
	for _, want := range []string{"APP_ENV=production\n", "DB_CONNECTION=mariadb\n", "QUEUE_CONNECTION=redis\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, bad := range []string{"hunter2", "secret", "Acme", "CACHE_STORE", "pass@host"} {
		if strings.Contains(got, bad) {
			t.Errorf("leaked %q in\n%s", bad, got)
		}
	}
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
}
