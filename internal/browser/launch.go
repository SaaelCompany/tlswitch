package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

type chromeProc struct {
	cmd    *exec.Cmd
	port   int
	stderr *ring
	done   chan struct{}
}

type ring struct {
	buf []byte
}

func (r *ring) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	if len(r.buf) > 8000 {
		r.buf = r.buf[len(r.buf)-8000:]
	}
	return len(p), nil
}

func findBrowser(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("browser.path: %w", err)
		}
		return explicit, nil
	}
	for _, p := range browserCandidates() {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if path, err := exec.LookPath("google-chrome"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("msedge"); err == nil {
		return path, nil
	}
	return "", errors.New("на сервере не найден Chrome или Edge. Установите один из них или укажите browser.path. Прокси при этом работает")
}

func browserCandidates() []string {
	if runtime.GOOS == "windows" {
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LOCALAPPDATA")
		return []string{
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
		}
	}
	return []string{
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/local/bin/google-chrome",
	}
}

func launchChrome(ctx context.Context, bin, profile string, noSandbox bool) (*chromeProc, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-sync",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-domain-reliability",
		"--disable-default-apps",
		"--disable-popup-blocking",
		"--disable-prompt-on-repost",
		"--metrics-recording-only",
		"--mute-audio",
		"--hide-scrollbars",
		"--disable-breakpad",
		"--disable-crash-reporter",
		"--no-service-autorun",
		"--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider",
		"--window-size=1280,800",
		"--disable-blink-features=AutomationControlled",
		"--user-agent=" + chromeUserAgent,
		"--remote-debugging-address=127.0.0.1",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--remote-allow-origins=*",
		"--user-data-dir=" + profile,
		"about:blank",
	}
	if noSandbox {
		args = append(args, "--no-sandbox", "--disable-setuid-sandbox")
	}
	if runtime.GOOS != "windows" {
		args = append(args, "--disable-dev-shm-usage")
	}
	cmd := exec.Command(bin, args...)
	cmd.SysProcAttr = procAttr()
	stderr := &ring{}
	cmd.Stderr = stderr
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	proc := &chromeProc{cmd: cmd, port: port, stderr: stderr, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(proc.done)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			killProcess(cmd)
			return nil, ctx.Err()
		}
		select {
		case <-proc.done:
			deadline = time.Time{}
		default:
		}
		if deadline.IsZero() {
			break
		}
		probe, err := (&http.Client{Timeout: 400 * time.Millisecond}).Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
		if err == nil {
			probe.Body.Close()
			if probe.StatusCode == 200 {
				return proc, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	killProcess(cmd)
	tail := string(stderr.buf)
	if tail == "" {
		tail = "процесс завершился без сообщения"
	}
	return nil, fmt.Errorf("браузер на сервере не запустил отладчик. Если это служба или контейнер, поставьте browser.no_sandbox: true. %s", tail)
}

type pageTarget struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func firstPage(ctx context.Context, port int) (pageTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/json/list", port), nil)
	if err != nil {
		return pageTarget{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return pageTarget{}, err
	}
	defer resp.Body.Close()
	var pages []pageTarget
	if err := json.NewDecoder(resp.Body).Decode(&pages); err != nil {
		return pageTarget{}, err
	}
	for _, p := range pages {
		if p.Type == "page" && p.WebSocketDebuggerURL != "" {
			return p, nil
		}
	}
	return pageTarget{}, errors.New("у браузера нет вкладки")
}
