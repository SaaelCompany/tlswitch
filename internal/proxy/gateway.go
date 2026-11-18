// Package proxy is an HTTP reverse proxy for an allowlist of government sites.
// The browser talks plain HTTP (or HTTPS with the gateway's own certificate).
// The gateway talks HTTPS to the site and checks the certificate itself.
package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/rewrite"
)

const maxRewrite = 8 << 20

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

type ctxKey int

const (
	infoKey ctxKey = iota
	acceptKey
)

type target struct {
	Host    string
	RawPath string
	Mode    rewrite.Mode
	Secure  bool
	Origin  string
}

// Gateway proxies an allowlist of sites.
type Gateway struct {
	allow *allow.List
	rp    *httputil.ReverseProxy
}

// New builds a gateway. tr is the upstream transport.
func New(list *allow.List, tr http.RoundTripper) *Gateway {
	g := &Gateway{allow: list}
	g.rp = &httputil.ReverseProxy{
		Rewrite:        g.rewrite,
		ModifyResponse: g.modify,
		ErrorHandler:   g.onError,
		Transport:      roundTripLogger{base: tr},
		FlushInterval:  -1,
	}
	return g
}

// ServeSW serves the path-mode service worker.
func (g *Gateway) ServeSW(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Service-Worker-Allowed", "/go/")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(serviceWorkerJS))
}

// ServePath handles /go/<host>/<path>.
func (g *Gateway) ServePath(w http.ResponseWriter, r *http.Request) {
	host, rawPath, err := splitGo(r.URL)
	if err != nil || !g.allow.Allows(host) {
		http.Error(w, "этот адрес не входит в список государственных сайтов", http.StatusForbidden)
		return
	}
	info := target{
		Host:    host,
		RawPath: rawPath,
		Mode:    rewrite.ModePath,
		Secure:  r.TLS != nil,
		Origin:  originOf(r),
	}
	g.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), infoKey, info)))
}

// ServeHost handles a request whose Host is itself a government site.
// Split DNS points that name at the gateway, and the browser uses http://.
func (g *Gateway) ServeHost(w http.ResponseWriter, r *http.Request) {
	host, err := allow.Normalize(stripPort(r.Host))
	if err != nil || !g.allow.Allows(host) {
		http.NotFound(w, r)
		return
	}
	raw := r.URL.EscapedPath()
	if raw == "" {
		raw = "/"
	}
	info := target{
		Host:    host,
		RawPath: raw,
		Mode:    rewrite.ModeHost,
		Secure:  r.TLS != nil,
		Origin:  originOf(r),
	}
	g.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), infoKey, info)))
}

// Allows reports whether a browser Host header should be proxied in host mode.
func (g *Gateway) Allows(host string) bool {
	n, err := allow.Normalize(stripPort(host))
	if err != nil {
		return false
	}
	return g.allow.Allows(n)
}

func (g *Gateway) rewrite(pr *httputil.ProxyRequest) {
	info, ok := pr.In.Context().Value(infoKey).(target)
	if !ok {
		pr.Out.URL.Scheme = "https"
		pr.Out.URL.Host = "invalid.invalid"
		return
	}
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = info.Host
	setEscapedPath(pr.Out.URL, info.RawPath)
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	pr.Out.Host = info.Host

	pr.Out.Header.Del("Accept-Encoding")
	pr.Out.Header.Del("Range")
	opt := g.opt(info)
	if ref := pr.Out.Header.Get("Referer"); ref != "" {
		if up := rewrite.ToUpstream(ref, opt); up != "" {
			pr.Out.Header.Set("Referer", up)
		} else {
			pr.Out.Header.Del("Referer")
		}
	}
	if pr.Out.Header.Get("Origin") != "" {
		pr.Out.Header.Set("Origin", "https://"+info.Host)
	}
	if ua := pr.Out.Header.Get("User-Agent"); ua == "" || strings.Contains(ua, "Go-http-client") {
		pr.Out.Header.Set("User-Agent", defaultUA)
	}
	ae := pr.In.Header.Get("Accept-Encoding")
	pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), acceptKey, ae))
}

func (g *Gateway) modify(resp *http.Response) error {
	info, ok := resp.Request.Context().Value(infoKey).(target)
	if !ok {
		return nil
	}
	opt := g.opt(info)
	rewriteResponseHeaders(resp, opt, info.Secure)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return nil
	}
	if resp.ContentLength > maxRewrite {
		return nil
	}
	ct := resp.Header.Get("Content-Type")
	if !textual(ct) {
		return nil
	}
	if enc := strings.ToLower(resp.Header.Get("Content-Encoding")); enc != "" && enc != "identity" {
		return nil
	}
	body, rest, tooBig, err := readMax(resp.Body, maxRewrite)
	if err != nil {
		return err
	}
	if tooBig {
		resp.Body = &bodyClose{Reader: io.MultiReader(bytes.NewReader(body), rest), Closer: resp.Body}
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
		return nil
	}
	_ = resp.Body.Close()
	rewritten := rewrite.Bytes(body, opt)
	if isHTML(ct) {
		rewritten = stripMetaCSP(rewritten)
		tag := injectTag(info.Mode, info.Host, g.allow.Suffixes())
		rewritten = injectHead(rewritten, tag)
	}
	var out io.Reader = bytes.NewReader(rewritten)
	if ae, _ := resp.Request.Context().Value(acceptKey).(string); len(rewritten) > 1024 && strings.Contains(ae, "gzip") {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(rewritten); err == nil && zw.Close() == nil && buf.Len() < len(rewritten) {
			resp.Header.Set("Content-Encoding", "gzip")
			resp.Header.Del("Content-Length")
			resp.ContentLength = int64(buf.Len())
			resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
			return nil
		}
	}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = int64(len(rewritten))
	resp.Body = io.NopCloser(out)
	return nil
}

func (g *Gateway) opt(info target) rewrite.Options {
	return rewrite.Options{
		Mode:   info.Mode,
		Origin: info.Origin,
		Host:   info.Host,
		Allow:  g.allow.Allows,
	}
}

func (g *Gateway) onError(w http.ResponseWriter, r *http.Request, err error) {
	msg := explain(err)
	log.Printf("proxy error %s %s: %s", r.Method, r.URL.Path, msg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, errorPage, htmlEscape(msg))
}

func explain(err error) string {
	var unk x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var inv x509.CertificateInvalidError
	switch {
	case errors.As(err, &unk):
		return "Сертификат сайта не входит в цепочку доверия. Шлюз не отключает проверку. Добавьте недостающий корневой сертификат в upstream.ca_file."
	case errors.As(err, &hostErr):
		return "Имя в сертификате не совпадает с адресом сайта."
	case errors.As(err, &inv):
		return "Сертификат сайта отклонён: " + inv.Error()
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "внутренний или локальный"):
		return "Соединение остановлено: имя сайта указывает на внутренний адрес."
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "TLS handshake") || strings.Contains(msg, "handshake failure"):
		return "Сайт не завершил обычное TLS-соединение. Если он принимает только ГОСТ-TLS (КриптоПро), этот шлюз к нему не подключится."
	default:
		if len(msg) > 280 {
			msg = msg[:280]
		}
		return "Не удалось открыть сайт: " + msg
	}
}

func rewriteResponseHeaders(resp *http.Response, opt rewrite.Options, secure bool) {
	h := resp.Header
	for _, name := range []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Report-To",
		"Nel",
		"Expect-Ct",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Resource-Policy",
		"Alt-Svc",
		"Alternate-Protocol",
		"Clear-Site-Data",
	} {
		h.Del(name)
	}
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
	if loc := h.Get("Location"); loc != "" {
		h.Set("Location", rewrite.URL(loc, opt))
	}
	if refresh := h.Get("Refresh"); refresh != "" {
		h.Set("Refresh", rewriteRefresh(refresh, opt))
	}
	cookies := h.Values("Set-Cookie")
	if len(cookies) > 0 {
		h.Del("Set-Cookie")
		for _, c := range cookies {
			h.Add("Set-Cookie", rewrite.SetCookie(c, opt, secure))
		}
	}
	if origin := h.Get("Access-Control-Allow-Origin"); origin != "" && origin != "*" {
		h.Set("Access-Control-Allow-Origin", rewrite.URL(origin, opt))
	}
}

func rewriteRefresh(v string, opt rewrite.Options) string {
	parts := strings.SplitN(v, ";", 2)
	if len(parts) < 2 {
		return v
	}
	tail := strings.TrimSpace(parts[1])
	if len(tail) < 4 || !strings.EqualFold(tail[:4], "url=") {
		return v
	}
	u := strings.Trim(strings.TrimSpace(tail[4:]), `"'`)
	return parts[0] + ";url=" + rewrite.URL(u, opt)
}

func splitGo(u *url.URL) (string, string, error) {
	esc := u.EscapedPath()
	if !strings.HasPrefix(esc, "/go/") {
		return "", "", errors.New("path")
	}
	rest := strings.TrimPrefix(esc, "/go/")
	h, p, found := strings.Cut(rest, "/")
	if !found {
		h = rest
		p = ""
	}
	if h == "" || h == "sw.js" {
		return "", "", errors.New("host")
	}
	un, err := url.PathUnescape(h)
	if err != nil {
		return "", "", err
	}
	host, err := allow.Normalize(un)
	if err != nil {
		return "", "", err
	}
	if p == "" {
		return host, "/", nil
	}
	return host, "/" + p, nil
}

func setEscapedPath(u *url.URL, escaped string) {
	if escaped == "" {
		escaped = "/"
	}
	if !strings.HasPrefix(escaped, "/") {
		escaped = "/" + escaped
	}
	unesc, err := url.PathUnescape(escaped)
	if err != nil {
		u.Path = escaped
		return
	}
	u.Path = unesc
	if (&url.URL{Path: unesc}).EscapedPath() != escaped {
		u.RawPath = escaped
	}
}

func originOf(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func textual(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/html", "application/xhtml+xml", "text/css",
		"text/javascript", "application/javascript", "application/x-javascript",
		"application/json", "text/json", "application/manifest+json",
		"application/xml", "text/xml", "image/svg+xml":
		return true
	default:
		return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
	}
}

func isHTML(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

func readMax(r io.Reader, n int) (buf []byte, rest io.Reader, tooBig bool, err error) {
	buf, err = io.ReadAll(io.LimitReader(r, int64(n)+1))
	if err != nil {
		return nil, nil, false, err
	}
	if len(buf) > n {
		return buf[:n], io.MultiReader(bytes.NewReader(buf[n:]), r), true, nil
	}
	return buf, nil, false, nil
}

type bodyClose struct {
	io.Reader
	io.Closer
}

func stripMetaCSP(in []byte) []byte {
	lower := bytes.ToLower(in)
	var out []byte
	i := 0
	for i < len(in) {
		j := bytes.Index(lower[i:], []byte("<meta"))
		if j < 0 {
			out = append(out, in[i:]...)
			break
		}
		j += i
		endRel := bytes.IndexByte(lower[j:], '>')
		if endRel < 0 {
			out = append(out, in[i:]...)
			break
		}
		end := j + endRel
		if bytes.Contains(lower[j:end+1], []byte("content-security-policy")) {
			out = append(out, in[i:j]...)
			i = end + 1
			continue
		}
		out = append(out, in[i:end+1]...)
		i = end + 1
	}
	return out
}

func injectHead(html []byte, tag string) []byte {
	lower := bytes.ToLower(html)
	i := bytes.Index(lower, []byte("<head"))
	if i >= 0 {
		if j := bytes.IndexByte(html[i:], '>'); j >= 0 {
			at := i + j + 1
			out := make([]byte, 0, len(html)+len(tag))
			out = append(out, html[:at]...)
			out = append(out, tag...)
			out = append(out, html[at:]...)
			return out
		}
	}
	return append([]byte(tag), html...)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
	)
	return r.Replace(s)
}

const errorPage = `<!DOCTYPE html>
<meta charset="utf-8">
<title>tlswitch</title>
<body style="font-family:Segoe UI,sans-serif;max-width:40rem;margin:3rem auto;line-height:1.45;color:#1c2430">
<h1 style="font-size:1.25rem">Сайт не открылся</h1>
<p>%s</p>
<p><a href="/">На главную</a></p>
</body>`

type roundTripLogger struct {
	base http.RoundTripper
}

func (l roundTripLogger) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := l.base.RoundTrip(r)
	if err != nil {
		log.Printf("upstream %s %s%s: %v", r.Method, r.URL.Host, r.URL.Path, errShort(err))
		return nil, err
	}
	log.Printf("upstream %s %s%s -> %d %s", r.Method, r.URL.Host, r.URL.Path, resp.StatusCode, time.Since(start).Round(time.Millisecond))
	return resp, nil
}

func errShort(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
