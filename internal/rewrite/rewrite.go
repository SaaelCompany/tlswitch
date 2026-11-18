// Package rewrite turns absolute government URLs into addresses the user's
// browser can open without the Russian CA and without TLS 1.2.
package rewrite

import (
	"net"
	"net/url"
	"strings"
)

// Mode selects how links are rewritten.
type Mode int

const (
	// ModePath serves a site under /go/<host>/ on the gateway.
	ModePath Mode = iota
	// ModeHost serves a site on its own hostname over plain HTTP.
	ModeHost
)

// Options describes one proxied response.
type Options struct {
	Mode Mode
	// Origin is the gateway origin without a trailing slash, for example
	// http://10.0.0.5:8080. Used in path mode.
	Origin string
	// Host is the upstream site being proxied, without a port.
	Host string
	// Allow reports whether a hostname may be proxied.
	Allow func(host string) bool
}

// Bytes rewrites absolute http(s) and ws(s) URLs in a text body.
// Only the scheme and host are replaced; the path is left in place.
func Bytes(in []byte, opt Options) []byte {
	if opt.Allow == nil {
		opt.Allow = func(string) bool { return false }
	}
	out := make([]byte, 0, len(in)+64)
	for i := 0; i < len(in); {
		m, ok := matchURL(in, i)
		if !ok {
			out = append(out, in[i])
			i++
			continue
		}
		repl, changed := mapMatch(m, opt)
		if !changed {
			out = append(out, in[i:i+m.n]...)
			i += m.n
			continue
		}
		out = append(out, repl...)
		i += m.n
	}
	if opt.Mode == ModePath {
		out = rootRelative(out, "/go/"+opt.Host)
	}
	return out
}

// URL rewrites one URL: a Location header, a referer, or an attribute.
func URL(raw string, opt Options) string {
	if raw == "" {
		return raw
	}
	if opt.Allow == nil {
		opt.Allow = func(string) bool { return false }
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Host == "" {
		if opt.Mode == ModePath && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") && !strings.HasPrefix(u.Path, "/go/") {
			u.Path = "/go/" + opt.Host + u.Path
			if u.RawPath != "" {
				u.RawPath = "/go/" + opt.Host + u.RawPath
			}
			return u.String()
		}
		return raw
	}
	if !opt.Allow(u.Hostname()) {
		return raw
	}
	if opt.Mode == ModePath {
		nu := strings.TrimRight(opt.Origin, "/") + "/go/" + hostport(u) + escapedPath(u)
		if u.RawQuery != "" {
			nu += "?" + u.RawQuery
		}
		if u.Fragment != "" {
			nu += "#" + u.Fragment
		}
		return nu
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "ws"
	}
	return u.String()
}

// ToUpstream converts a browser URL back into the https URL of the site.
// This is used for Referer and Origin, which the site expects to be its own.
func ToUpstream(raw string, opt Options) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if opt.Mode == ModePath {
		esc := u.EscapedPath()
		if !strings.HasPrefix(esc, "/go/") {
			return "https://" + opt.Host + "/"
		}
		rest := strings.TrimPrefix(esc, "/go/")
		host, path, found := strings.Cut(rest, "/")
		if !found {
			host = rest
			path = ""
		}
		if host == "" {
			return ""
		}
		nu := "https://" + host + "/" + path
		if u.RawQuery != "" {
			nu += "?" + u.RawQuery
		}
		return nu
	}
	if u.Host == "" {
		return raw
	}
	if !opt.Allow(u.Hostname()) {
		return ""
	}
	switch u.Scheme {
	case "http", "https":
		u.Scheme = "https"
	case "ws", "wss":
		u.Scheme = "wss"
	}
	return u.String()
}

// SetCookie rewrites one Set-Cookie header.
// secureOK is true when the browser connection itself is HTTPS.
// In path mode, Domain is removed and Path is pinned under /go/<host>
// so two sites on one gateway do not share cookies.
func SetCookie(raw string, opt Options, secureOK bool) string {
	parts := splitSemi(raw)
	if len(parts) == 0 {
		return raw
	}
	out := []string{parts[0]}
	sameSite := ""
	wrotePath := false
	for _, p := range parts[1:] {
		name, value, hasValue := strings.Cut(p, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "domain":
			if opt.Mode == ModeHost && hasValue {
				out = append(out, p)
			}
		case "secure":
			if secureOK {
				out = append(out, "Secure")
			}
		case "path":
			wrotePath = true
			if opt.Mode == ModePath {
				path := "/"
				if hasValue {
					path = value
				}
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				out = append(out, "Path="+pathJoin("/go/"+opt.Host, path))
			} else {
				out = append(out, p)
			}
		case "samesite":
			sameSite = value
			if !secureOK && strings.EqualFold(value, "None") {
				out = append(out, "SameSite=Lax")
			} else {
				out = append(out, p)
			}
		default:
			out = append(out, p)
		}
	}
	if opt.Mode == ModePath && !wrotePath {
		out = append(out, "Path=/go/"+opt.Host)
	}
	_ = sameSite
	return strings.Join(out, "; ")
}

type urlMatch struct {
	scheme  string
	host    string
	escaped bool
	n       int
	raw     string
}

func matchURL(in []byte, i int) (urlMatch, bool) {
	rest := in[i:]
	type pref struct {
		s       string
		scheme  string
		escaped bool
	}
	prefs := []pref{
		{"https://", "https", false},
		{"http://", "http", false},
		{"wss://", "wss", false},
		{"ws://", "ws", false},
		{`https:\/\/`, "https", true},
		{`http:\/\/`, "http", true},
		{`wss:\/\/`, "wss", true},
		{`ws:\/\/`, "ws", true},
	}
	for _, p := range prefs {
		if len(rest) < len(p.s) || !hasPrefixFold(rest, p.s) {
			continue
		}
		host, n, ok := scanHost(rest[len(p.s):], p.escaped)
		if !ok {
			return urlMatch{}, false
		}
		total := len(p.s) + n
		return urlMatch{
			scheme:  p.scheme,
			host:    host,
			escaped: p.escaped,
			n:       total,
			raw:     string(rest[:total]),
		}, true
	}
	return urlMatch{}, false
}

func hasPrefixFold(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := b[i]
		w := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if w >= 'A' && w <= 'Z' {
			w += 'a' - 'A'
		}
		if c != w {
			return false
		}
	}
	return true
}

func scanHost(b []byte, escaped bool) (string, int, bool) {
	var host []byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			host = append(host, c)
		case c == ':' && !bytesContains(host, ':'):
			// Port, or the start of an escaped slash ":\/\/" which is not a host.
			if escaped && i+1 < len(b) && b[i+1] == '\\' {
				return "", 0, false
			}
			host = append(host, c)
		default:
			if len(host) == 0 || !strings.Contains(string(host), ".") {
				return "", 0, false
			}
			return string(host), i, true
		}
	}
	if len(host) == 0 || !strings.Contains(string(host), ".") {
		return "", 0, false
	}
	return string(host), len(b), true
}

func bytesContains(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func mapMatch(m urlMatch, opt Options) ([]byte, bool) {
	hostOnly := m.host
	if h, p, err := net.SplitHostPort(m.host); err == nil {
		if p != "443" {
			return nil, false
		}
		hostOnly = h
	}
	if !opt.Allow(hostOnly) {
		return nil, false
	}
	host := hostOnly
	if opt.Mode == ModeHost {
		var scheme string
		if m.scheme == "http" || m.scheme == "ws" {
			return nil, false
		}
		if m.scheme == "wss" {
			scheme = "ws"
		} else {
			scheme = "http"
		}
		if m.escaped {
			return []byte(scheme + `:\/\/` + host), true
		}
		return []byte(scheme + "://" + host), true
	}
	baseOrigin := opt.Origin
	if m.scheme == "ws" || m.scheme == "wss" {
		baseOrigin = toWebSocketOrigin(opt.Origin)
	}
	base := strings.TrimRight(baseOrigin, "/") + "/go/" + host
	if m.escaped {
		return []byte(strings.ReplaceAll(base, "/", `\/`)), true
	}
	return []byte(base), true
}

func toWebSocketOrigin(origin string) string {
	switch {
	case strings.HasPrefix(origin, "https://"):
		return "wss://" + strings.TrimPrefix(origin, "https://")
	case strings.HasPrefix(origin, "http://"):
		return "ws://" + strings.TrimPrefix(origin, "http://")
	default:
		return origin
	}
}

func rootRelative(in []byte, prefix string) []byte {
	if prefix == "" {
		return in
	}
	out := make([]byte, 0, len(in)+32)
	for i := 0; i < len(in); {
		if n, ok := matchRootAttr(in, i); ok {
			out = append(out, in[i:i+n]...)
			out = append(out, prefix...)
			i += n
			continue
		}
		if n, ok := matchCSSRoot(in, i); ok {
			out = append(out, in[i:i+n]...)
			out = append(out, prefix...)
			i += n
			continue
		}
		out = append(out, in[i])
		i++
	}
	return out
}

// matchRootAttr matches the quote before a root-relative attribute value.
// The caller inserts the prefix between the quote and the slash... wait, the
// slash is NOT consumed. We match up to and including the opening quote of
// href="/ so the prefix is inserted before the slash.
func matchRootAttr(in []byte, i int) (int, bool) {
	attrs := []string{`href="`, `href='`, `src="`, `src='`, `action="`, `action='`, `poster="`, `poster='`}
	rest := in[i:]
	for _, a := range attrs {
		if len(rest) < len(a)+1 || !hasPrefixFold(rest, a) {
			continue
		}
		// Require a word boundary of sorts: start or a non-letter before.
		if i > 0 {
			p := in[i-1]
			if (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') {
				continue
			}
		}
		slash := rest[len(a)]
		if slash != '/' {
			continue
		}
		if len(rest) > len(a)+1 && rest[len(a)+1] == '/' {
			continue
		}
		// Skip values that already point at the gateway.
		if hasPrefixFold(rest[len(a):], "/go/") {
			continue
		}
		return len(a), true
	}
	return 0, false
}

func matchCSSRoot(in []byte, i int) (int, bool) {
	rest := in[i:]
	if len(rest) < 5 || !hasPrefixFold(rest, "url(") {
		return 0, false
	}
	j := 4
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
		j++
	}
	if j >= len(rest) {
		return 0, false
	}
	if rest[j] == '"' || rest[j] == '\'' {
		j++
	}
	if j >= len(rest) || rest[j] != '/' {
		return 0, false
	}
	if j+1 < len(rest) && rest[j+1] == '/' {
		return 0, false
	}
	if hasPrefixFold(rest[j:], "/go/") {
		return 0, false
	}
	return j, true
}

func hostport(u *url.URL) string {
	if _, port, err := net.SplitHostPort(u.Host); err == nil && port == "443" {
		return u.Hostname()
	}
	return u.Host
}

func escapedPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func pathJoin(prefix, path string) string {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + path
}

func splitSemi(s string) []string {
	raw := strings.Split(s, ";")
	var out []string
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
