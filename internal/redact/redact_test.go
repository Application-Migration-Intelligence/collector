package redact

import (
	"strings"
	"testing"
)

func TestMasksSecrets(t *testing.T) {
	cases := map[string]string{
		"DB_PASSWORD=hunter2":                          "DB_PASSWORD=" + Mask,
		"export API_KEY=abc123":                        "export API_KEY=" + Mask,
		"  stripe_secret: sk_live_x":                   "  stripe_secret: " + Mask,
		"'password' => 'hunter2',":                     "'password' => '" + Mask + "',",
		`"client_secret" => "abc",`:                    `"client_secret" => "` + Mask + `",`,
		`{"api_key": "abc\"def"}`:                      `{"api_key": "` + Mask + `"}`,
		"redis://user:pa55@localhost:6379":             "redis://user:" + Mask + "@localhost:6379",
		"key AKIAABCDEFGHIJKLMNOP here":                "key " + Mask + " here",
		"APP_KEY=base64:" + strings.Repeat("A", 44):    "APP_KEY=" + Mask,
		"token ghp_" + strings.Repeat("a", 36) + " ok": "token " + Mask + " ok",
		"fastcgi_param DB_PASSWORD hunter2;":           "fastcgi_param DB_PASSWORD " + Mask + ";",
		"SetEnv APP_KEY \"abc\"":                       "SetEnv APP_KEY " + Mask,
		"env[DB_PASSWORD] = hunter2":                   "env[DB_PASSWORD] = " + Mask,
		`Environment="STRIPE_SECRET=abc" "X=1"`:        `Environment="STRIPE_SECRET=` + Mask + `" "X=1"`,
		"environment=APP_ENV=prod,API_TOKEN=abc":       "environment=APP_ENV=prod,API_TOKEN=" + Mask,
		"* * * * * API_TOKEN=abc123 php artisan x":     "* * * * * API_TOKEN=" + Mask + " php artisan x",
	}
	for in, want := range cases {
		got, n := Text(in)
		if got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
		if n == 0 {
			t.Errorf("Text(%q) reported no redactions", in)
		}
	}
}

func TestKeepsHarmlessText(t *testing.T) {
	for _, in := range []string{
		"DB_CONNECTION=mariadb",
		"'password' => env('DB_PASSWORD', ''),",
		"DB_PASSWORD=",
		"$token = $request->bearerToken();",
		"https://example.com/path",
	} {
		if got, n := Text(in); got != in || n != 0 {
			t.Errorf("Text(%q) = %q (%d), want unchanged", in, got, n)
		}
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	in := "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nb"
	got, _ := Text(in)
	if strings.Contains(got, "MIIE") || !strings.Contains(got, Mask) {
		t.Fatalf("private key not masked: %q", got)
	}
}

func TestRulesAndCastsStay(t *testing.T) {
	for _, in := range []string{
		"'password' => 'hashed',",
		"'password' => 'required|string|min:8|confirmed',",
		"'mfa_secret' => 'encrypted',",
	} {
		if got, n := Text(in); got != in || n != 0 {
			t.Errorf("Text(%q) = %q", in, got)
		}
	}
	if got, _ := Text("'password' => 'hunter2',"); !strings.Contains(got, Mask) {
		t.Errorf("a real password stayed: %q", got)
	}
}

func TestFormatsLeavesPackageNames(t *testing.T) {
	in := `"ext-tokenizer": "*", "url": "https://user:pw@repo.example/x", "token": "ghp_` + strings.Repeat("a", 36) + `"`
	got, n := Formats(in)
	if !strings.Contains(got, `"ext-tokenizer": "*"`) || strings.Contains(got, ":pw@") || strings.Contains(got, "ghp_") || n != 2 {
		t.Errorf("Formats = %q (%d)", got, n)
	}
}
