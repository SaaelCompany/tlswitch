// Package catalog stores sites added from the start page.
package catalog

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/config"
)

// Site is one start-page entry. Custom entries were added in the interface.
type Site struct {
	Title  string `json:"title"`
	URL    string `json:"url"`
	Note   string `json:"note"`
	Custom bool   `json:"custom"`
}

// Catalog is the start page plus hostnames the gateway may open.
type Catalog struct {
	mu      sync.Mutex
	path    string
	allow   *allow.List
	added   map[string]bool
	builtin []Site
	custom  []Site
}

// Open loads previously added sites and permits their hostnames.
func Open(path string, list *allow.List, builtin []config.PortalSite) (*Catalog, error) {
	c := &Catalog{path: path, allow: list, added: map[string]bool{}}
	for _, s := range builtin {
		c.builtin = append(c.builtin, Site{Title: s.Title, URL: s.URL, Note: s.Note})
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return nil, err
	}
	var saved []Site
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &saved); err != nil {
			return nil, err
		}
	}
	for _, s := range saved {
		s.Custom = true
		if _, host, err := clean(s.URL, s.Title); err == nil {
			if !list.Allows(host) {
				c.added[host] = true
			}
			_ = list.Add(host)
			c.custom = append(c.custom, s)
		}
	}
	return c, nil
}

// Sites returns the built-in entries followed by ones added in the interface.
func (c *Catalog) Sites() []Site {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Site, 0, len(c.builtin)+len(c.custom))
	out = append(out, c.builtin...)
	out = append(out, c.custom...)
	return out
}

// Add checks the address, remembers it, and permits that hostname.
func (c *Catalog) Add(rawURL, title string) (Site, error) {
	site, host, err := clean(rawURL, title)
	if err != nil {
		return Site{}, err
	}
	site.Custom = true
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, s := range c.custom {
		if sameURL(s.URL, site.URL) {
			c.custom[i] = site
			return site, c.saveLocked()
		}
	}
	if len(c.custom) >= 50 {
		return Site{}, errors.New("уже добавлено 50 сайтов")
	}
	fresh := !c.allow.Allows(host)
	if err := c.allow.Add(host); err != nil {
		return Site{}, err
	}
	if fresh {
		c.added[host] = true
	}
	c.custom = append(c.custom, site)
	if err := c.saveLocked(); err != nil {
		c.custom = c.custom[:len(c.custom)-1]
		if fresh {
			c.allow.Remove(host)
			delete(c.added, host)
		}
		return Site{}, err
	}
	return site, nil
}

// Remove deletes a site that was added in the interface.
func (c *Catalog) Remove(rawURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.custom[:0]
	var removed string
	for _, s := range c.custom {
		if sameURL(s.URL, rawURL) {
			removed = s.URL
			continue
		}
		next = append(next, s)
	}
	if removed == "" {
		return errors.New("такого сайта нет в списке")
	}
	c.custom = next
	if host := hostOf(removed); host != "" && c.added[host] && !c.hostUsedLocked(host) {
		c.allow.Remove(host)
		delete(c.added, host)
	}
	return c.saveLocked()
}

func (c *Catalog) hostUsedLocked(host string) bool {
	for _, s := range append(append([]Site{}, c.builtin...), c.custom...) {
		if strings.EqualFold(hostOf(s.URL), host) {
			return true
		}
	}
	return false
}

func (c *Catalog) saveLocked() error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c.custom, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func clean(rawURL, title string) (Site, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if len(rawURL) > 500 {
		return Site{}, "", errors.New("слишком длинный адрес")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return Site{}, "", errors.New("нужен адрес вида https://имя-сайта")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Site{}, "", errors.New("нужен адрес http или https")
	}
	host, err := allow.Normalize(u.Hostname())
	if err != nil {
		return Site{}, "", err
	}
	if strings.Count(host, ".") < 1 {
		return Site{}, "", errors.New("укажите полное имя сайта, не весь домен")
	}
	u.Scheme = "https"
	u.Host = host
	u.User = nil
	title = strings.TrimSpace(title)
	if title == "" {
		title = host
	}
	if len([]rune(title)) > 80 {
		title = string([]rune(title)[:80])
	}
	return Site{Title: title, URL: u.String(), Note: "Добавлен на этом сервере"}, host, nil
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h, err := allow.Normalize(u.Hostname())
	if err != nil {
		return ""
	}
	return h
}

func sameURL(a, b string) bool {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(a)), "/") == strings.TrimRight(strings.ToLower(strings.TrimSpace(b)), "/")
}
