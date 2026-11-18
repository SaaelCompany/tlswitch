// Package allow decides which hostnames the gateway may contact.
package allow

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// List is a set of DNS suffixes. A host matches when it is the suffix or a
// subdomain of it. Matching is done on punycode, so look-alike Unicode names
// do not pass.
type List struct {
	suffixes []string
}

// New builds a list. Empty input is an error: an empty allowlist must not
// mean "every host".
func New(suffixes []string) (*List, error) {
	if len(suffixes) == 0 {
		return nil, fmt.Errorf("список разрешённых имён пуст")
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range suffixes {
		n, err := Normalize(s)
		if err != nil {
			return nil, fmt.Errorf("суффикс %q: %w", s, err)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return &List{suffixes: out}, nil
}

// Allows reports whether host is on the list. Ports and a trailing dot are ignored.
func (l *List) Allows(host string) bool {
	n, err := Normalize(host)
	if err != nil {
		return false
	}
	for _, s := range l.suffixes {
		if n == s || strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}

// Suffixes returns the normalized suffixes.
func (l *List) Suffixes() []string {
	out := make([]string, len(l.suffixes))
	copy(out, l.suffixes)
	return out
}

// Normalize lowercases a host, converts it to punycode and rejects IP addresses.
func Normalize(host string) (string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", fmt.Errorf("пустое имя")
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p != "" && p != "443" {
			return "", fmt.Errorf("поддерживается только порт 443")
		}
		host = h
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("ip-адрес вместо имени")
	}
	if strings.ContainsAny(host, " /\\@?#%") {
		return "", fmt.Errorf("недопустимое имя")
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") {
		return "", fmt.Errorf("недопустимое имя")
	}
	if net.ParseIP(ascii) != nil {
		return "", fmt.Errorf("ip-адрес вместо имени")
	}
	return ascii, nil
}
