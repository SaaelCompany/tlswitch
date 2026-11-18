package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const pageHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Браузер на сервере</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: #12161c; color: #f4f7fb; font-family: "Segoe UI", sans-serif; }
  header { display: flex; gap: 8px; align-items: center; padding: 8px; background: #1c2430; }
  button, input { font: inherit; }
  button { background: #2a3544; color: inherit; border: 0; border-radius: 8px; padding: 8px 10px; cursor: pointer; }
  button:hover { background: #36485c; }
  input[type=url] { flex: 1; min-width: 0; background: #0e131a; color: inherit; border: 1px solid #314052; border-radius: 8px; padding: 8px 10px; }
  #stage { position: relative; height: calc(100% - 52px); display: flex; align-items: center; justify-content: center; overflow: hidden; }
  #view { max-width: 100%; max-height: 100%; background: #fff; cursor: default; outline: none; }
  #bar { position: absolute; left: 12px; bottom: 12px; display: flex; gap: 8px; align-items: center; }
  .toast { background: #f4f7fb; color: #1c2430; border-radius: 10px; padding: 10px 12px; box-shadow: 0 8px 24px rgba(0,0,0,.3); }
  #msg { position: absolute; top: 12px; left: 12px; right: 12px; }
  a { color: #0b3a66; }
  .hidden { display: none; }
</style>
</head>
<body>
<header>
  <a href="/"><button type="button" title="На главную">←</button></a>
  <button type="button" id="back" title="Назад">←</button>
  <button type="button" id="fwd" title="Вперёд">→</button>
  <button type="button" id="reload" title="Обновить">↻</button>
  <input id="url" type="url" spellcheck="false" placeholder="https://www.gosuslugi.ru">
  <button type="button" id="go">Открыть</button>
</header>
<div id="stage">
  <div id="msg"></div>
  <img id="view" alt="Страница на сервере" tabindex="0">
  <div id="bar"></div>
</div>
<script>
(function () {
  const params = new URLSearchParams(location.search);
  const start = params.get("url") || "https://www.gosuslugi.ru";
  const img = document.getElementById("view");
  const urlInput = document.getElementById("url");
  const msg = document.getElementById("msg");
  const bar = document.getElementById("bar");
  urlInput.value = start;
  let ws, blobURL;
  function note(text) {
    msg.innerHTML = '<div class="toast">' + text + '</div>';
  }
  function clearNote() { msg.textContent = ""; }
  function send(obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }
  function connect(id) {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(proto + "://" + location.host + "/api/sessions/" + id + "/ws");
    ws.binaryType = "arraybuffer";
    ws.onopen = function () {
      clearNote();
      const r = img.parentElement.getBoundingClientRect();
      send({type:"size", w: Math.round(r.width), h: Math.round(r.height)});
    };
    ws.onmessage = function (ev) {
      if (typeof ev.data !== "string") {
        const blob = new Blob([ev.data], {type:"image/jpeg"});
        const next = URL.createObjectURL(blob);
        img.src = next;
        if (blobURL) URL.revokeObjectURL(blobURL);
        blobURL = next;
        return;
      }
      const m = JSON.parse(ev.data);
      if (m.type === "status" && m.url) urlInput.value = m.url;
      if (m.type === "file-request") showFile();
      if (m.type === "download") showDownload(m);
      if (m.type === "clipboard" && m.text && navigator.clipboard) navigator.clipboard.writeText(m.text).catch(function(){});
      if (m.type === "error") note(escapeHTML(m.message || "ошибка"));
    };
    ws.onclose = function () { note("Сессия закрыта. <a href=\"/\">На главную</a>"); };
  }
  function escapeHTML(s) {
    return String(s).replace(/[&<>"]/g, function (c) { return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]; });
  }
  function showFile() {
    bar.innerHTML = '<div class="toast">Сайт просит файл <input id="file" type="file"></div>';
    document.getElementById("file").onchange = function () {
      const f = this.files && this.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = function () {
        const data = String(reader.result).split(",")[1] || "";
        send({type:"file", name: f.name, data: data});
        bar.innerHTML = "";
      };
      reader.readAsDataURL(f);
    };
  }
  function showDownload(m) {
    const a = document.createElement("a");
    a.className = "toast";
    a.href = m.url;
    a.textContent = "Скачать " + (m.name || "файл");
    bar.appendChild(a);
  }
  function pos(ev) {
    const r = img.getBoundingClientRect();
    const sx = img.naturalWidth ? (ev.clientX - r.left) * (img.naturalWidth / r.width) : 0;
    const sy = img.naturalHeight ? (ev.clientY - r.top) * (img.naturalHeight / r.height) : 0;
    return {x: sx, y: sy};
  }
  img.addEventListener("mousedown", function (ev) { img.focus(); const p = pos(ev); send({type:"mouse", event:"down", x:p.x, y:p.y, button: ev.button}); ev.preventDefault(); });
  img.addEventListener("mouseup", function (ev) { const p = pos(ev); send({type:"mouse", event:"up", x:p.x, y:p.y, button: ev.button}); });
  img.addEventListener("mousemove", function (ev) { const p = pos(ev); send({type:"mouse", event:"move", x:p.x, y:p.y, button: ev.button}); });
  img.addEventListener("wheel", function (ev) { const p = pos(ev); send({type:"mouse", event:"wheel", x:p.x, y:p.y, deltaX: ev.deltaX, deltaY: ev.deltaY}); ev.preventDefault(); }, {passive:false});
  img.addEventListener("contextmenu", function (ev) { ev.preventDefault(); });
  document.addEventListener("keydown", function (ev) {
    if (document.activeElement === urlInput) return;
    if (ev.key === "v" && (ev.ctrlKey || ev.metaKey)) return;
    send({type:"key", event:"down", key: ev.key, code: ev.code, keyCode: ev.keyCode, alt: ev.altKey, ctrl: ev.ctrlKey, shift: ev.shiftKey, meta: ev.metaKey});
    if (ev.key.length === 1 && !ev.ctrlKey && !ev.metaKey) send({type:"key", event:"char", text: ev.key});
    ev.preventDefault();
  });
  document.addEventListener("keyup", function (ev) {
    if (document.activeElement === urlInput) return;
    send({type:"key", event:"up", key: ev.key, code: ev.code, keyCode: ev.keyCode, alt: ev.altKey, ctrl: ev.ctrlKey, shift: ev.shiftKey, meta: ev.metaKey});
  });
  document.addEventListener("paste", function (ev) {
    if (document.activeElement === urlInput) return;
    const text = ev.clipboardData && ev.clipboardData.getData("text");
    if (text) send({type:"paste", text: text});
    ev.preventDefault();
  });
  document.getElementById("back").onclick = function () { send({type:"back"}); };
  document.getElementById("fwd").onclick = function () { send({type:"forward"}); };
  document.getElementById("reload").onclick = function () { send({type:"reload"}); };
  document.getElementById("go").onclick = openURL;
  urlInput.addEventListener("keydown", function (ev) { if (ev.key === "Enter") openURL(); });
  function openURL() { send({type:"nav", url: urlInput.value}); img.focus(); }
  window.addEventListener("resize", function () {
    const r = img.parentElement.getBoundingClientRect();
    send({type:"size", w: Math.round(r.width), h: Math.round(r.height)});
  });
  note("Запускается браузер на сервере…");
  fetch("/api/sessions", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({url: start})})
    .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || "не удалось открыть сессию"); return j; }); })
    .then(function (j) { connect(j.id); })
    .catch(function (e) { note(escapeHTML(e.message)); });
})();
</script>
</body>
</html>
`

func (m *Manager) ServePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = io.WriteString(w, pageHTML)
}

func (m *Manager) ServeAPI(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		writeErr(w, http.StatusServiceUnavailable, "браузер на сервере выключен")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	switch {
	case path == "status" && r.Method == http.MethodGet:
		ok, msg := m.Available()
		writeJSON(w, http.StatusOK, map[string]any{"browser": ok, "error": msg})
	case path == "sessions" && r.Method == http.MethodPost:
		m.createSession(w, r)
	case strings.HasPrefix(path, "sessions/"):
		m.sessionRoute(w, r, strings.TrimPrefix(path, "sessions/"))
	default:
		http.NotFound(w, r)
	}
}

func (m *Manager) createSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	if err := dec.Decode(&body); err != nil || body.URL == "" {
		writeErr(w, http.StatusBadRequest, "нужен адрес сайта")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	s, err := m.create(ctx, body.URL)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": s.id})
}

func (m *Manager) sessionRoute(w http.ResponseWriter, r *http.Request, rest string) {
	id, action, _ := strings.Cut(rest, "/")
	s := m.get(id)
	if s == nil {
		writeErr(w, http.StatusNotFound, "сессия не найдена")
		return
	}
	switch {
	case action == "ws":
		m.serveWS(w, r, s)
	case strings.HasPrefix(action, "downloads/"):
		m.serveDownload(w, r, s, strings.TrimPrefix(action, "downloads/"))
	case action == "" && r.Method == http.MethodDelete:
		m.drop(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (m *Manager) serveDownload(w http.ResponseWriter, r *http.Request, s *session, name string) {
	name = filepath.Base(name)
	if name == "" || name == "." || name == ".." {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.downloads, name)
	f, err := os.Open(path)
	if err != nil {
		// Chrome sometimes keeps the suggested name exactly.
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, time.Now(), f)
}

func (m *Manager) serveWS(w http.ResponseWriter, r *http.Request, s *session) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	conn.SetReadLimit(32 << 20)
	defer conn.Close(websocket.StatusNormalClosure, "bye")
	s.mu.Lock()
	s.viewer = conn
	s.viewers++
	s.lastActive = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.viewer == conn {
			s.viewer = nil
		}
		s.viewers--
		s.lastActive = time.Now()
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				cancel()
				return
			}
			s.onClient(ctx, data)
		}
	}()
	s.pushStatus(false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.frames.ch:
			jpeg := s.frames.get()
			if len(jpeg) == 0 {
				continue
			}
			wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
			err := s.writeFrame(wctx, websocket.MessageBinary, jpeg)
			wcancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *session) onClient(ctx context.Context, data []byte) {
	s.touch()
	var msg struct {
		Type    string  `json:"type"`
		Event   string  `json:"event"`
		X       float64 `json:"x"`
		Y       float64 `json:"y"`
		Button  int     `json:"button"`
		DeltaX  float64 `json:"deltaX"`
		DeltaY  float64 `json:"deltaY"`
		Key     string  `json:"key"`
		Code    string  `json:"code"`
		Text    string  `json:"text"`
		KeyCode int     `json:"keyCode"`
		Alt     bool    `json:"alt"`
		Ctrl    bool    `json:"ctrl"`
		Shift   bool    `json:"shift"`
		Meta    bool    `json:"meta"`
		URL     string  `json:"url"`
		W       int     `json:"w"`
		H       int     `json:"h"`
		Name    string  `json:"name"`
		Data    string  `json:"data"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	switch msg.Type {
	case "mouse":
		kind := "mouseMoved"
		switch msg.Event {
		case "down":
			kind = "mousePressed"
		case "up":
			kind = "mouseReleased"
		case "wheel":
			kind = "mouseWheel"
		}
		button := "none"
		buttons := 0
		switch msg.Button {
		case 0:
			button = "left"
			if msg.Event == "down" || msg.Event == "move" {
				buttons = 1
			}
		case 1:
			button = "middle"
		case 2:
			button = "right"
			if msg.Event == "down" {
				buttons = 2
			}
		}
		if msg.Event == "up" || msg.Event == "move" && msg.Event != "down" {
			if msg.Event != "down" {
				buttons = 0
			}
		}
		params := map[string]any{
			"type": kind, "x": msg.X, "y": msg.Y, "button": button, "buttons": buttons, "clickCount": 1,
		}
		if kind == "mouseWheel" {
			params["deltaX"] = msg.DeltaX
			params["deltaY"] = msg.DeltaY
		}
		_, _ = s.cdp.Call(cctx, "Input.dispatchMouseEvent", params)
	case "key":
		if msg.Event == "char" && msg.Text != "" {
			_, _ = s.cdp.Call(cctx, "Input.insertText", map[string]any{"text": msg.Text})
			return
		}
		kind := "keyDown"
		if msg.Event == "up" {
			kind = "keyUp"
		}
		mod := 0
		if msg.Alt {
			mod |= 1
		}
		if msg.Ctrl {
			mod |= 2
		}
		if msg.Meta {
			mod |= 4
		}
		if msg.Shift {
			mod |= 8
		}
		_, _ = s.cdp.Call(cctx, "Input.dispatchKeyEvent", map[string]any{
			"type": kind, "key": msg.Key, "code": msg.Code,
			"windowsVirtualKeyCode": msg.KeyCode, "nativeVirtualKeyCode": msg.KeyCode,
			"modifiers": mod,
		})
	case "paste":
		if msg.Text != "" && len(msg.Text) <= 100000 {
			_, _ = s.cdp.Call(cctx, "Input.insertText", map[string]any{"text": msg.Text})
		}
	case "nav":
		if err := s.navigate(cctx, msg.URL); err != nil {
			s.sendJSON(map[string]any{"type": "error", "message": err.Error()})
		}
	case "back":
		s.history(cctx, -1)
	case "forward":
		s.history(cctx, 1)
	case "reload":
		_, _ = s.cdp.Call(cctx, "Page.reload", map[string]any{})
	case "size":
		_ = s.resize(cctx, msg.W, msg.H)
	case "file":
		s.acceptFile(cctx, msg.Name, msg.Data)
	}
}

func (s *session) history(ctx context.Context, delta int) {
	raw, err := s.cdp.Call(ctx, "Page.getNavigationHistory", map[string]any{})
	if err != nil {
		return
	}
	var hist struct {
		CurrentIndex int `json:"currentIndex"`
		Entries      []struct {
			ID int `json:"id"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &hist) != nil {
		return
	}
	idx := hist.CurrentIndex + delta
	if idx < 0 || idx >= len(hist.Entries) {
		return
	}
	_, _ = s.cdp.Call(ctx, "Page.navigateToHistoryEntry", map[string]any{"entryId": hist.Entries[idx].ID})
}

func (s *session) acceptFile(ctx context.Context, name, data string) {
	s.mu.Lock()
	node := s.fileNode
	s.mu.Unlock()
	if node == 0 {
		s.sendJSON(map[string]any{"type": "error", "message": "Сначала нажмите поле выбора файла на сайте."})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(raw) == 0 || len(raw) > 20<<20 {
		s.sendJSON(map[string]any{"type": "error", "message": "Файл не принят. Лимит 20 МБ."})
		return
	}
	name = safeName(name)
	if name == "" {
		name = "upload"
	}
	path := filepath.Join(s.uploads, strconv.FormatInt(time.Now().UnixNano(), 10)+"-"+name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		s.sendJSON(map[string]any{"type": "error", "message": "Не удалось сохранить файл на сервере."})
		return
	}
	_, err = s.cdp.Call(ctx, "DOM.setFileInputFiles", map[string]any{
		"files":         []string{path},
		"backendNodeId": node,
	})
	if err != nil {
		s.sendJSON(map[string]any{"type": "error", "message": "Сайт не принял файл."})
		return
	}
	s.mu.Lock()
	s.fileNode = 0
	s.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
