// Package server is the HTTP front of tlswitch.
package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/browser"
	"github.com/SaaelCompany/tlswitch/internal/catalog"
	"github.com/SaaelCompany/tlswitch/internal/certs"
	"github.com/SaaelCompany/tlswitch/internal/config"
	"github.com/SaaelCompany/tlswitch/internal/gosttls"
	"github.com/SaaelCompany/tlswitch/internal/portal"
	"github.com/SaaelCompany/tlswitch/internal/proxy"
	"github.com/SaaelCompany/tlswitch/internal/upstream"
)

// Server is the running gateway.
type Server struct {
	cfg     *config.File
	allow   *allow.List
	proxy   *proxy.Gateway
	portal  *portal.Page
	catalog *catalog.Catalog
	browser *browser.Manager
	tr      *upstream.Transport
}

// Load reads a config file and builds the gateway.
func Load(path string) (*Server, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// New builds the gateway from configuration.
func New(cfg *config.File) (*Server, error) {
	list, err := allow.New(cfg.AllowSuffixes)
	if err != nil {
		return nil, err
	}
	material, err := certs.Load(cfg.ExtraCA)
	if err != nil {
		return nil, err
	}
	minTLS, err := tlsVersion(cfg.Upstream.MinTLS)
	if err != nil {
		return nil, err
	}
	client, err := loadClient(cfg)
	if err != nil {
		return nil, err
	}
	tr, err := upstream.NewFromMaterial(material, upstream.Options{
		MinTLS:       minTLS,
		DNS:          cfg.Upstream.DNS,
		Proxy:        cfg.Upstream.Proxy,
		AllowPrivate: cfg.Upstream.AllowPrivate,
		Client:       client,
	})
	if err != nil {
		return nil, err
	}
	dataDir := dataDirOf(cfg)
	cat, err := catalog.Open(filepath.Join(dataDir, "sites.json"), list, cfg.Portal)
	if err != nil {
		return nil, err
	}
	br := browser.NewManager(browser.Options{
		Allow:       list,
		BrowserPath: cfg.Browser.Path,
		DataDir:     dataDir,
		Material:    material,
		MaxSessions: cfg.Browser.MaxSessions,
		Idle:        cfg.IdleTimeout,
		Quality:     cfg.Browser.Quality,
		MaxWidth:    cfg.Browser.MaxWidth,
		MaxHeight:   cfg.Browser.MaxHeight,
		NoSandbox:   cfg.Browser.NoSandbox,
		Enabled:     cfg.Browser.Enabled,
	})
	return &Server{
		cfg:   cfg,
		allow: list,
		proxy: proxy.New(list, tr),
		portal: portal.New(func() []portal.Entry {
			sites := cat.Sites()
			out := make([]portal.Entry, len(sites))
			for i, s := range sites {
				out[i] = portal.Entry{Title: s.Title, Note: s.Note, URL: s.URL, Custom: s.Custom}
			}
			return out
		}),
		catalog: cat,
		browser: br,
		tr:      tr,
	}, nil
}

// Handler is the public HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.guard(http.HandlerFunc(s.route))
}

// Listen serves until ctx is cancelled.
func (s *Server) Listen(ctx context.Context) error {
	defer s.Close()
	errCh := make(chan error, 2)
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		log.Printf("слушаю http://%s", s.cfg.Listen)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	var tlsSrv *http.Server
	if s.cfg.TLSListen != "" {
		tlsSrv = &http.Server{
			Addr:              s.cfg.TLSListen,
			Handler:           s.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
		go func() {
			log.Printf("слушаю https://%s", s.cfg.TLSListen)
			err := tlsSrv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		if tlsSrv != nil {
			_ = tlsSrv.Shutdown(shut)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Close releases browser sessions and idle connections.
func (s *Server) Close() {
	if s.browser != nil {
		s.browser.Close()
	}
	if s.tr != nil {
		s.tr.CloseIdleConnections()
	}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	case r.URL.Path == "/robots.txt":
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	case r.URL.Path == "/go/sw.js":
		s.proxy.ServeSW(w, r)
	case strings.HasPrefix(r.URL.Path, "/go/"):
		s.proxy.ServePath(w, r)
	case r.URL.Path == "/browser" || r.URL.Path == "/browser/":
		s.browser.ServePage(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		s.browser.ServeAPI(w, r)
	case s.proxy.Allows(r.Host):
		s.proxy.ServeHost(w, r)
	case r.URL.Path == "/sites" && r.Method == http.MethodPost:
		s.addSite(w, r)
	case r.URL.Path == "/sites/delete" && r.Method == http.MethodPost:
		s.deleteSite(w, r)
	case r.URL.Path == "/":
		s.portal.ServeHTTP(w, r)
	default:
		if host := hostFromReferer(r); host != "" && s.proxy.Allows(host) {
			s.proxyReferer(w, r, host)
			return
		}
		http.NotFound(w, r)
	}
}

func (s *Server) addSite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape("не удалось прочитать форму"), http.StatusSeeOther)
		return
	}
	if _, err := s.catalog.Add(r.FormValue("url"), r.FormValue("title")); err != nil {
		http.Redirect(w, r, "/?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = s.catalog.Remove(r.FormValue("url"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// hostFromReferer recovers the government host when the page asks the gateway
// for a root path such as /__jsch or /auth. Those requests used to be a 404
// in the middle of login.
func hostFromReferer(r *http.Request) string {
	ref := r.Referer()
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/go/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/go/")
	host, _, _ := strings.Cut(rest, "/")
	host, err = url.PathUnescape(host)
	if err != nil || host == "" || host == "sw.js" {
		return ""
	}
	return host
}

func (s *Server) proxyReferer(w http.ResponseWriter, r *http.Request, host string) {
	u := *r.URL
	suffix := r.URL.EscapedPath()
	if suffix == "" {
		suffix = "/"
	}
	u.Path = "/go/" + host + suffix
	u.RawPath = ""
	r2 := r.Clone(r.Context())
	r2.URL = &u
	r2.RequestURI = u.RequestURI()
	s.proxy.ServePath(w, r2)
}

func loadClient(cfg *config.File) (*gosttls.Identity, error) {
	certPath := strings.TrimSpace(cfg.Upstream.ClientCert)
	keyPath := strings.TrimSpace(cfg.Upstream.ClientKey)
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("нужны оба файла: upstream.client_cert и upstream.client_key")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("upstream.client_cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("upstream.client_key: %w", err)
	}
	return gosttls.LoadIdentity(certPEM, keyPEM)
}

func dataDirOf(cfg *config.File) string {
	dir := cfg.DataDir
	if dir == "" {
		dir = "data"
	}
	if !filepath.IsAbs(dir) {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Join(filepath.Dir(exe), dir)
		}
	}
	return dir
}

func (s *Server) guard(next http.Handler) http.Handler {
	user, pass := s.cfg.AuthUser, s.cfg.AuthPassword
	nets := s.cfg.ClientNets
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !clientAllowed(r, nets) {
			http.Error(w, "адрес не разрешён", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/healthz" || (user == "" && pass == "") {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="tlswitch"`)
			http.Error(w, "нужна авторизация", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientAllowed(r *http.Request, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func tlsVersion(s string) (uint16, error) {
	switch s {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("неизвестная версия TLS %q", s)
	}
}
