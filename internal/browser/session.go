package browser

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/certs"
)

// Manager runs server-side browser sessions.
type Manager struct {
	allow       *allow.List
	bin         string
	binErr      string
	dataDir     string
	material    *certs.Material
	maxSessions int
	idle        time.Duration
	quality     int
	maxW        int
	maxH        int
	noSandbox   bool

	mu       sync.Mutex
	sessions map[string]*session
	stop     chan struct{}
	policy   sync.Once
	polErr   error
}

// Options configures the manager.
type Options struct {
	Allow       *allow.List
	BrowserPath string
	DataDir     string
	Material    *certs.Material
	MaxSessions int
	Idle        time.Duration
	Quality     int
	MaxWidth    int
	MaxHeight   int
	NoSandbox   bool
	Enabled     bool
}

// NewManager prepares sessions. A missing browser is reported by Available
// and does not stop the rest of the gateway.
func NewManager(opt Options) *Manager {
	if opt.MaxSessions <= 0 {
		opt.MaxSessions = 4
	}
	if opt.Idle <= 0 {
		opt.Idle = 20 * time.Minute
	}
	if opt.Quality <= 0 {
		opt.Quality = 70
	}
	m := &Manager{
		allow:       opt.Allow,
		dataDir:     opt.DataDir,
		material:    opt.Material,
		maxSessions: opt.MaxSessions,
		idle:        opt.Idle,
		quality:     opt.Quality,
		maxW:        opt.MaxWidth,
		maxH:        opt.MaxHeight,
		noSandbox:   opt.NoSandbox,
		sessions:    map[string]*session{},
		stop:        make(chan struct{}),
	}
	if !opt.Enabled {
		m.binErr = "браузер на сервере выключен в конфигурации"
		return m
	}
	bin, err := findBrowser(opt.BrowserPath)
	if err != nil {
		m.binErr = err.Error()
	} else {
		m.bin = bin
	}
	go m.gc()
	return m
}

// Available reports whether a server-side browser can be started.
func (m *Manager) Available() (bool, string) {
	if m == nil || m.bin == "" {
		if m == nil {
			return false, "браузер на сервере выключен"
		}
		return false, m.binErr
	}
	return true, ""
}

// Close stops every session.
func (m *Manager) Close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.mu.Lock()
	all := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.sessions = map[string]*session{}
	m.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}

func (m *Manager) gc() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.sweep()
		}
	}
}

func (m *Manager) sweep() {
	m.mu.Lock()
	var dead []string
	for id, s := range m.sessions {
		s.mu.Lock()
		idle := time.Since(s.lastActive)
		viewers := s.viewers
		s.mu.Unlock()
		if (viewers == 0 && idle > 45*time.Second) || idle > m.idle {
			dead = append(dead, id)
		}
	}
	m.mu.Unlock()
	for _, id := range dead {
		m.drop(id)
	}
}

func (m *Manager) ensurePolicy() error {
	m.policy.Do(func() {
		if m.material == nil {
			m.polErr = errors.New("нет сертификатов")
			return
		}
		m.polErr = installFromMaterial(m.material)
	})
	return m.polErr
}

func (m *Manager) create(ctx context.Context, rawURL string) (*session, error) {
	if m.bin == "" {
		return nil, errors.New(m.binErr)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !allowedNavigation(u, m.allow) {
		return nil, errors.New("этот адрес не входит в список государственных сайтов")
	}
	if u.Scheme == "http" {
		u.Scheme = "https"
	}
	if err := m.ensurePolicy(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		return nil, fmt.Errorf("уже открыто %d сессий, закройте одну из них", m.maxSessions)
	}
	m.mu.Unlock()

	id, err := newID()
	if err != nil {
		return nil, err
	}
	profile := filepath.Join(m.dataDir, "sess-"+id)
	if err := os.MkdirAll(filepath.Join(profile, "downloads"), 0o700); err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Join(profile, "uploads"), 0o700)
	proc, err := launchChrome(ctx, m.bin, profile, m.noSandbox)
	if err != nil {
		_ = os.RemoveAll(profile)
		return nil, err
	}
	page, err := firstPage(ctx, proc.port)
	if err != nil {
		killProcess(proc.cmd)
		_ = os.RemoveAll(profile)
		return nil, err
	}
	cdp, err := dialCDP(ctx, page.WebSocketDebuggerURL)
	if err != nil {
		killProcess(proc.cmd)
		_ = os.RemoveAll(profile)
		return nil, err
	}
	s := &session{
		id:         id,
		allow:      m.allow,
		proc:       proc,
		profile:    profile,
		downloads:  filepath.Join(profile, "downloads"),
		uploads:    filepath.Join(profile, "uploads"),
		cdp:        cdp,
		frames:     newMailbox(),
		lastActive: time.Now(),
		files:      map[string]string{},
		quality:    m.quality,
		maxW:       m.maxW,
		maxH:       m.maxH,
	}
	cdp.onEvent = s.onEvent
	if err := s.boot(ctx, u.String()); err != nil {
		s.close()
		return nil, err
	}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	log.Printf("browser session %s %s", id, u.Hostname())
	return s, nil
}

func (m *Manager) drop(id string) {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s != nil {
		s.close()
		log.Printf("browser session %s closed", id)
	}
}

func (m *Manager) get(id string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

type session struct {
	id         string
	allow      *allow.List
	proc       *chromeProc
	profile    string
	downloads  string
	uploads    string
	cdp        *cdpConn
	frames     *mailbox
	quality    int
	maxW       int
	maxH       int
	mu         sync.Mutex
	lastActive time.Time
	viewers    int
	closed     bool
	viewer     *websocket.Conn
	writeMu    sync.Mutex
	fileNode   int
	files      map[string]string
	pageURL    string
}

func (s *session) boot(ctx context.Context, start string) error {
	if _, err := s.cdp.Call(ctx, "Page.enable", map[string]any{}); err != nil {
		return err
	}
	_, _ = s.cdp.Call(ctx, "Network.enable", map[string]any{})
	_, _ = s.cdp.Call(ctx, "Network.setUserAgentOverride", map[string]any{
		"userAgent": chromeUserAgent,
		"platform":  "Win32",
	})
	_, _ = s.cdp.Call(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{
		"source": "Object.defineProperty(navigator, 'webdriver', {get: function(){ return undefined; }});",
	})
	if _, err := s.cdp.Call(ctx, "Page.setInterceptFileChooserDialog", map[string]any{"enabled": true}); err != nil {
		return err
	}
	_, _ = s.cdp.Call(ctx, "Browser.setDownloadBehavior", map[string]any{
		"behavior":      "allow",
		"downloadPath":  s.downloads,
		"eventsEnabled": true,
	})
	if _, err := s.cdp.Call(ctx, "Fetch.enable", map[string]any{
		"patterns": []map[string]any{{"urlPattern": "*", "requestStage": "Request"}},
	}); err != nil {
		return err
	}
	if err := s.resize(ctx, 1280, 800); err != nil {
		return err
	}
	if err := s.screencast(ctx); err != nil {
		return err
	}
	return s.navigate(ctx, start)
}

func (s *session) screencast(ctx context.Context) error {
	_, err := s.cdp.Call(ctx, "Page.startScreencast", map[string]any{
		"format":        "jpeg",
		"quality":       s.quality,
		"maxWidth":      s.maxW,
		"maxHeight":     s.maxH,
		"everyNthFrame": 1,
	})
	return err
}

func (s *session) resize(ctx context.Context, w, h int) error {
	if w < 320 {
		w = 320
	}
	if h < 240 {
		h = 240
	}
	if s.maxW > 0 && w > s.maxW {
		w = s.maxW
	}
	if s.maxH > 0 && h > s.maxH {
		h = s.maxH
	}
	_, err := s.cdp.Call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{
		"width":             w,
		"height":            h,
		"deviceScaleFactor": 1,
		"mobile":            false,
	})
	return err
}

func (s *session) navigate(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !allowedNavigation(u, s.allow) {
		return errors.New("этот адрес не входит в список государственных сайтов")
	}
	if u.Scheme == "http" {
		u.Scheme = "https"
	}
	_, err = s.cdp.Call(ctx, "Page.navigate", map[string]any{"url": u.String()})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pageURL = u.String()
	s.lastActive = time.Now()
	s.mu.Unlock()
	s.pushStatus(true)
	return nil
}

func (s *session) onEvent(method string, params json.RawMessage) {
	switch method {
	case "Page.screencastFrame":
		var ev struct {
			Data      string `json:"data"`
			SessionID int    `json:"sessionId"`
		}
		if json.Unmarshal(params, &ev) == nil {
			if jpeg, err := base64.StdEncoding.DecodeString(ev.Data); err == nil {
				s.frames.put(jpeg)
			}
			s.cdp.Notify("Page.screencastFrameAck", map[string]any{"sessionId": ev.SessionID})
		}
	case "Fetch.requestPaused":
		s.onPaused(params)
	case "Page.fileChooserOpened":
		var ev struct {
			BackendNodeID int `json:"backendNodeId"`
		}
		_ = json.Unmarshal(params, &ev)
		s.mu.Lock()
		s.fileNode = ev.BackendNodeID
		s.mu.Unlock()
		s.sendJSON(map[string]any{"type": "file-request"})
	case "Page.frameNavigated":
		var ev struct {
			Frame struct {
				ParentID string `json:"parentId"`
				URL      string `json:"url"`
			} `json:"frame"`
		}
		if json.Unmarshal(params, &ev) == nil && ev.Frame.ParentID == "" && ev.Frame.URL != "" {
			s.mu.Lock()
			s.pageURL = ev.Frame.URL
			s.mu.Unlock()
			s.pushStatus(false)
		}
	case "Page.frameStartedLoading":
		s.pushStatus(true)
	case "Page.loadEventFired":
		s.pushStatus(false)
	case "Browser.downloadWillBegin":
		var ev struct {
			GUID              string `json:"guid"`
			SuggestedFilename string `json:"suggestedFilename"`
		}
		if json.Unmarshal(params, &ev) == nil {
			name := safeName(ev.SuggestedFilename)
			if name == "" {
				name = ev.GUID
			}
			s.mu.Lock()
			s.files[ev.GUID] = name
			s.mu.Unlock()
		}
	case "Browser.downloadProgress":
		var ev struct {
			GUID  string `json:"guid"`
			State string `json:"state"`
		}
		if json.Unmarshal(params, &ev) == nil && ev.State == "completed" {
			s.mu.Lock()
			name := s.files[ev.GUID]
			s.mu.Unlock()
			if name != "" {
				s.sendJSON(map[string]any{
					"type": "download",
					"name": name,
					"url":  "/api/sessions/" + s.id + "/downloads/" + url.PathEscape(name),
				})
			}
		}
	}
}

func (s *session) onPaused(params json.RawMessage) {
	var ev struct {
		RequestID string `json:"requestId"`
		Request   struct {
			URL string `json:"url"`
		} `json:"request"`
	}
	if json.Unmarshal(params, &ev) != nil || ev.RequestID == "" {
		return
	}
	u, err := url.Parse(ev.Request.URL)
	if err != nil || !allowedRequest(u, s.allow) {
		s.cdp.Notify("Fetch.failRequest", map[string]any{
			"requestId":   ev.RequestID,
			"errorReason": "BlockedByClient",
		})
		return
	}
	s.cdp.Notify("Fetch.continueRequest", map[string]any{"requestId": ev.RequestID})
}

func (s *session) pushStatus(loading bool) {
	s.mu.Lock()
	u := s.pageURL
	s.mu.Unlock()
	s.sendJSON(map[string]any{"type": "status", "url": u, "loading": loading})
}

func (s *session) sendJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.writeFrame(ctx, websocket.MessageText, b)
}

func (s *session) writeFrame(ctx context.Context, kind websocket.MessageType, b []byte) error {
	s.mu.Lock()
	conn := s.viewer
	s.mu.Unlock()
	if conn == nil {
		return errors.New("нет зрителя")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return conn.Write(ctx, kind, b)
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.cdp != nil {
		s.cdp.Close()
	}
	if s.proc != nil {
		killProcess(s.proc.cmd)
		select {
		case <-s.proc.done:
		case <-time.After(3 * time.Second):
		}
	}
	if s.profile != "" {
		_ = os.RemoveAll(s.profile)
	}
}

func (s *session) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

type mailbox struct {
	mu  sync.Mutex
	cur []byte
	ch  chan struct{}
}

func newMailbox() *mailbox {
	return &mailbox{ch: make(chan struct{}, 1)}
}

func (m *mailbox) put(b []byte) {
	cp := make([]byte, len(b))
	copy(cp, b)
	m.mu.Lock()
	m.cur = cp
	m.mu.Unlock()
	select {
	case m.ch <- struct{}{}:
	default:
	}
}

func (m *mailbox) get() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return nil
	}
	out := m.cur
	m.cur = nil
	return out
}

func allowedNavigation(u *url.URL, list *allow.List) bool {
	if u == nil || list == nil {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	return list.Allows(u.Hostname())
}

func allowedRequest(u *url.URL, list *allow.List) bool {
	if u == nil {
		return false
	}
	switch u.Scheme {
	case "about", "data", "blob", "chrome-error":
		return true
	case "http", "https", "ws", "wss":
		return list.Allows(u.Hostname())
	default:
		return false
	}
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func safeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r >= 0x400 && r <= 0x4FF:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}
