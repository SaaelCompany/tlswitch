package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/certs"
	"github.com/SaaelCompany/tlswitch/internal/upstream"
)

func TestPathProxyRewrites(t *testing.T) {
	ca, caPEM, leaf := mint(t, "example.com")
	upstreamSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Errorf("upstream was not TLS")
		}
		if r.Host != "example.com" {
			t.Errorf("upstream host %q", r.Host)
		}
		if r.URL.Path != "/pay" {
			t.Errorf("upstream path %q", r.URL.Path)
		}
		if got := r.Header.Get("Origin"); got != "https://example.com" {
			t.Errorf("origin %q", got)
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "upgrade-insecure-requests")
		w.Header().Set("Set-Cookie", "sid=abc; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=None")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests"></head><body><a href="https://example.com/next">n</a><a href="/lk">l</a></body></html>`)
	}))
	upstreamSrv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	upstreamSrv.StartTLS()
	defer upstreamSrv.Close()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tr, err := upstream.NewFromMaterial(&certs.Material{Roots: roots, Certificates: []*x509.Certificate{ca}}, upstream.Options{
		MinTLS:       tls.VersionTLS12,
		AllowPrivate: true,
		Override:     map[string]string{"example.com:443": upstreamSrv.Listener.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := allow.New([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	gw := New(list, tr)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/go/sw.js":
			gw.ServeSW(w, r)
		case strings.HasPrefix(r.URL.Path, "/go/"):
			gw.ServePath(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/go/example.com/pay", nil)
	req.Header.Set("Origin", front.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, text)
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS leaked")
	}
	if strings.Contains(resp.Header.Get("Content-Security-Policy"), "upgrade-insecure-requests") {
		t.Fatal("upgrade CSP leaked")
	}
	cookie := resp.Header.Get("Set-Cookie")
	if strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "Path=/go/example.com") {
		t.Fatalf("cookie %s", cookie)
	}
	if !strings.Contains(text, front.URL+"/go/example.com/next") {
		t.Fatalf("link not rewritten: %s", text)
	}
	if !strings.Contains(text, `href="/go/example.com/lk"`) {
		t.Fatalf("root link not rewritten: %s", text)
	}
	if strings.Contains(strings.ToLower(text), "content-security-policy") {
		t.Fatalf("meta csp kept: %s", text)
	}
	if !strings.Contains(text, "data-tlswitch") {
		t.Fatal("script not injected")
	}

	blocked, err := http.Get(front.URL + "/go/evil.example/")
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status %d", blocked.StatusCode)
	}
}

func TestProxyAcceptsDuplicateChunkedEncoding(t *testing.T) {
	ca, caPEM, leaf := mint(t, "example.com")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	page := []byte(`<!DOCTYPE html><html><body><p>открылось</p></body></html>`)
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(page), page)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				req.Body.Close()
				_, _ = io.WriteString(c, raw)
			}(c)
		}
	}()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tr, err := upstream.NewFromMaterial(&certs.Material{Roots: roots, Certificates: []*x509.Certificate{ca}}, upstream.Options{
		AllowPrivate: true,
		Override:     map[string]string{"example.com:443": ln.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := allow.New([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	gw := New(list, tr)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/go/") {
			gw.ServePath(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer front.Close()

	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Get(front.URL + "/go/example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, text)
	}
	if strings.Contains(text, "Сайт не открылся") || !strings.Contains(text, "открылось") {
		t.Fatalf("page %s", text)
	}
}

func mint(t *testing.T, host string) (*x509.Certificate, []byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pair
}
