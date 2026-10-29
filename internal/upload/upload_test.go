package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const key = "mig_ck_0123456789abcdefghij"

func TestCheckEndpoint(t *testing.T) {
	good := map[string]string{
		"https://migrateintel.com":      "https://migrateintel.com" + Path,
		"https://WWW.MigrateIntel.net/": "https://www.migrateintel.net" + Path,
		"https://migrateintel.com:443":  "https://migrateintel.com" + Path,
	}
	for in, want := range good {
		got, err := CheckEndpoint(in)
		if err != nil || got != want {
			t.Errorf("CheckEndpoint(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{
		"http://migrateintel.com", "https://evil.example", "https://migrateintel.com.evil.example",
		"https://user:pw@migrateintel.com", "https://migrateintel.com/other", "https://migrateintel.com:8443",
	} {
		if _, err := CheckEndpoint(bad); err == nil {
			t.Errorf("CheckEndpoint(%q) accepted", bad)
		}
	}
}

func TestSend(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.tar.gz")
	if err := os.WriteFile(file, []byte("package-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("package-bytes"))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path != Path || r.Method != http.MethodPost:
			w.WriteHeader(http.StatusNotFound)
		case r.Header.Get("Authorization") != "Bearer "+key:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"key_invalid","message":"This key was already used."}`))
		case r.Header.Get("X-Mig-Package-Sha256") != hex.EncodeToString(sum[:]) || string(body) != "package-bytes":
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"package_id":"pkg_1","project_url":"https://migrateintel.com/projects/1"}`))
		}
	}))
	defer srv.Close()

	c := New("test")
	c.HTTP.Transport = srv.Client().Transport
	res, err := c.Send(context.Background(), srv.URL+Path, key, file)
	if err != nil || res.PackageID != "pkg_1" {
		t.Fatalf("Send = %+v, %v", res, err)
	}

	_, err = c.Send(context.Background(), srv.URL+Path, "mig_ck_wrongwrongwrongwrong", file)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected the intake's message, got %v", err)
	}

	if _, err := c.Send(context.Background(), srv.URL+Path, "short", file); err == nil {
		t.Fatal("malformed key accepted")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.tar.gz")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New("test")
	c.HTTP.Transport = srv.Client().Transport
	if _, err := c.Send(context.Background(), srv.URL+Path, key, file); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect: %v", err)
	}
}
