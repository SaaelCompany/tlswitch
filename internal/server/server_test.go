package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaaelCompany/tlswitch/internal/config"
)

func TestPortalAuthAndBlock(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(writeCfg(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Enabled = false
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	front := httptest.NewServer(srv.Handler())
	defer front.Close()

	res, err := http.Get(front.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}

	res, err = http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("portal without auth %d", res.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.SetBasicAuth("user", "secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "Госуслуги") {
		t.Fatalf("portal %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "/go/www.gosuslugi.ru/") {
		t.Fatalf("missing proxy link: %s", body)
	}

	req, _ = http.NewRequest(http.MethodGet, front.URL+"/go/evil.example/", nil)
	req.SetBasicAuth("user", "secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("evil %d", res.StatusCode)
	}
}

func writeCfg(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "tlswitch.yaml")
	text := []byte("listen: 127.0.0.1:0\nauth_user: user\nauth_password: secret\nbrowser:\n  enabled: false\n")
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
