package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if !strings.Contains(string(body), "/go/www.gosuslugi.ru/") || !strings.Contains(string(body), "Добавить сайт") {
		t.Fatalf("missing proxy link: %s", body)
	}

	form := url.Values{}
	form.Set("title", "Кабинет")
	form.Set("url", "https://lk.example.ru/cabinet")
	req, _ = http.NewRequest(http.MethodPost, front.URL+"/sites", strings.NewReader(form.Encode()))
	req.SetBasicAuth("user", "secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("add site %d", res.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.SetBasicAuth("user", "secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "lk.example.ru") || !strings.Contains(string(body), "/go/lk.example.ru/") {
		t.Fatalf("added site missing: %s", body)
	}
	if hostFromReferer(mustReq(t, "/__jsch/static/script.js", front.URL+"/go/esia.gosuslugi.ru/login/")) != "esia.gosuslugi.ru" {
		t.Fatal("referer host")
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

func TestThumbprintPastedIntoClientCert(t *testing.T) {
	cfg := &config.File{}
	cfg.Upstream.ClientCert = "e0 d6 68 bc 76 c3 76 63 98 8e f4 18 c4 a5 97 1a 24 2f 29 f9"
	cfg.Upstream.ClientKey = "12345678"
	_, err := loadClient(cfg)
	if err == nil || strings.Contains(err.Error(), "cannot find") || strings.Contains(err.Error(), "open ") {
		t.Fatal(err)
	}
}

func mustReq(t *testing.T, path, referer string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://gateway"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Referer", referer)
	return req
}

func writeCfg(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "tlswitch.yaml")
	text := []byte(fmt.Sprintf("listen: 127.0.0.1:0\nauth_user: user\nauth_password: secret\ndata_dir: %q\nbrowser:\n  enabled: false\n", dir))
	if err := os.WriteFile(p, text, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
