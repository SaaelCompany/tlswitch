package rewrite

import (
	"strings"
	"testing"
)

func allowGov(host string) bool {
	host = strings.ToLower(host)
	return host == "gosuslugi.ru" || strings.HasSuffix(host, ".gosuslugi.ru") || host == "gu-st.ru" || strings.HasSuffix(host, ".gu-st.ru")
}

func TestBytesPath(t *testing.T) {
	opt := Options{Mode: ModePath, Origin: "http://10.0.0.5:8080", Host: "www.gosuslugi.ru", Allow: allowGov}
	in := []byte(`<a href="https://www.gosuslugi.ru/pay">x</a><a href="/lk">y</a><img src="https://gu-st.ru/a.png">`)
	got := string(Bytes(in, opt))
	wantSub := []string{
		`href="http://10.0.0.5:8080/go/www.gosuslugi.ru/pay"`,
		`href="/go/www.gosuslugi.ru/lk"`,
		`src="http://10.0.0.5:8080/go/gu-st.ru/a.png"`,
	}
	for _, w := range wantSub {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
	js := []byte(`{"url":"https:\/\/esia.gosuslugi.ru\/aas\/oauth2"}`)
	got = string(Bytes(js, opt))
	if !strings.Contains(got, `http:\/\/10.0.0.5:8080\/go\/esia.gosuslugi.ru\/aas\/oauth2`) {
		t.Fatalf("json rewrite: %s", got)
	}
}

func TestOAuthRedirectStays(t *testing.T) {
	opt := Options{Mode: ModePath, Origin: "http://10.0.0.5:8080", Host: "esia.gosuslugi.ru", Allow: allowGov}
	in := []byte(`redirect_uri=https://www.gosuslugi.ru/auth/cb&next=https://esia.gosuslugi.ru/login <base href="/">`)
	got := string(Bytes(in, opt))
	if !strings.Contains(got, "redirect_uri=https://www.gosuslugi.ru/auth/cb") {
		t.Fatalf("redirect_uri rewritten: %s", got)
	}
	if !strings.Contains(got, "http://10.0.0.5:8080/go/esia.gosuslugi.ru/login") {
		t.Fatalf("login url not rewritten: %s", got)
	}
	if !strings.Contains(got, `<base href="/go/esia.gosuslugi.ru/">`) {
		t.Fatalf("base: %s", got)
	}
}

func TestBytesHost(t *testing.T) {
	opt := Options{Mode: ModeHost, Host: "www.gosuslugi.ru", Allow: allowGov}
	in := []byte(`https://www.gosuslugi.ru/a http://www.gosuslugi.ru/b https://evil.example/c`)
	got := string(Bytes(in, opt))
	if !strings.Contains(got, "http://www.gosuslugi.ru/a") {
		t.Fatalf("https not rewritten: %s", got)
	}
	if !strings.Contains(got, "http://www.gosuslugi.ru/b") {
		t.Fatalf("http link lost: %s", got)
	}
	if !strings.Contains(got, "https://evil.example/c") {
		t.Fatalf("foreign link rewritten: %s", got)
	}
}

func TestDoesNotMatchLookalike(t *testing.T) {
	opt := Options{Mode: ModeHost, Host: "www.gosuslugi.ru", Allow: allowGov}
	in := []byte(`https://gosuslugi.ru.evil.com/a https://notgosuslugi.ru/b`)
	got := string(Bytes(in, opt))
	if got != string(in) {
		t.Fatalf("lookalike rewritten: %s", got)
	}
}

func TestSetCookie(t *testing.T) {
	opt := Options{Mode: ModePath, Host: "www.gosuslugi.ru", Allow: allowGov}
	raw := "sid=abc; Domain=.gosuslugi.ru; Path=/; Secure; HttpOnly; SameSite=None"
	got := SetCookie(raw, opt, false)
	if strings.Contains(got, "Secure") {
		t.Fatalf("secure kept on http: %s", got)
	}
	if strings.Contains(strings.ToLower(got), "domain=") {
		t.Fatalf("domain kept in path mode: %s", got)
	}
	if !strings.Contains(got, "Path=/go/www.gosuslugi.ru") {
		t.Fatalf("path: %s", got)
	}
	if !strings.Contains(got, "SameSite=Lax") {
		t.Fatalf("samesite: %s", got)
	}
	if !strings.Contains(got, "HttpOnly") || !strings.Contains(got, "sid=abc") {
		t.Fatalf("cookie value lost: %s", got)
	}
}

func TestToUpstream(t *testing.T) {
	opt := Options{Mode: ModePath, Origin: "http://gate:8080", Host: "www.gosuslugi.ru", Allow: allowGov}
	got := ToUpstream("http://gate:8080/go/esia.gosuslugi.ru/aas?x=1", opt)
	if got != "https://esia.gosuslugi.ru/aas?x=1" {
		t.Fatalf("got %s", got)
	}
}
