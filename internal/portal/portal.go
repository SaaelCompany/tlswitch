package portal

import (
	"html/template"
	"net/http"
	"net/url"

	"github.com/SaaelCompany/tlswitch/internal/allow"
	"github.com/SaaelCompany/tlswitch/internal/config"
)

// Page is the start page.
type Page struct {
	sites []config.PortalSite
}

// New builds the start page.
func New(sites []config.PortalSite) *Page {
	return &Page{sites: sites}
}

// ServeHTTP writes the start page.
func (p *Page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type card struct {
		Title     string
		Note      string
		Browser   string
		Proxy     string
		ProxyHost string
	}
	var cards []card
	for _, s := range p.sites {
		u, err := url.Parse(s.URL)
		if err != nil || u.Host == "" {
			continue
		}
		host, err := allow.Normalize(u.Hostname())
		if err != nil {
			continue
		}
		if u.Scheme == "" {
			u.Scheme = "https"
		}
		cards = append(cards, card{
			Title:     s.Title,
			Note:      s.Note,
			Browser:   "/browser/?url=" + url.QueryEscape(u.String()),
			Proxy:     "/go/" + host + "/",
			ProxyHost: host,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = pageTmpl.Execute(w, cards)
}

var pageTmpl = template.Must(template.New("portal").Parse(`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tlswitch — доступ к государственным сайтам</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; font-family: "Segoe UI", sans-serif; background: #f3f6f8; color: #1c2430; }
  header { background: #0b3a66; color: white; padding: 28px 20px 22px; }
  header h1 { margin: 0 0 8px; font-size: 1.6rem; font-weight: 650; }
  header p { margin: 0; max-width: 46rem; line-height: 1.45; }
  main { max-width: 64rem; margin: 0 auto; padding: 20px; }
  .warn { background: #fff8e8; border: 1px solid #ead7a1; border-radius: 12px; padding: 14px 16px; line-height: 1.45; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 14px; margin-top: 16px; }
  article { background: white; border-radius: 14px; padding: 16px; box-shadow: 0 1px 2px rgba(16, 32, 51, .06); display: flex; flex-direction: column; gap: 8px; }
  h2 { margin: 0; font-size: 1.05rem; }
  .note { margin: 0; color: #526173; flex: 1; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  a.btn { text-decoration: none; border-radius: 8px; padding: 8px 10px; font-size: .95rem; }
  a.primary { background: #0b3a66; color: white; }
  a.secondary { background: #e7eef5; color: #0b3a66; }
  footer { color: #526173; font-size: .9rem; line-height: 1.45; }
  code { font-family: ui-monospace, monospace; }
</style>
</head>
<body>
<header>
  <h1>Доступ к государственным сайтам</h1>
  <p>Браузер пользователя ничего не устанавливает. Сервер сам открывает сайт по TLS и проверяет сертификат Минцифры.</p>
</header>
<main>
  <div class="warn">
    Для входа через ЕСИА выбирайте «На сервере»: страница открывается в Chrome или Edge на этом сервере, а вы видите её в своём браузере.
    «Через прокси» легче и быстрее, но форма входа часто возвращает браузер на настоящий https-адрес мимо шлюза.
    Пароли, введённые в режиме «На сервере», видны этому серверу. Не публикуйте порт в интернет без пароля в конфигурации.
  </div>
  <div class="grid">
    {{range .}}
    <article>
      <h2>{{.Title}}</h2>
      <p class="note">{{.Note}}</p>
      <div class="actions">
        <a class="btn primary" href="{{.Browser}}">На сервере</a>
        <a class="btn secondary" href="{{.Proxy}}">Через прокси</a>
      </div>
    </article>
    {{end}}
  </div>
  <footer>
    <p>Прокси открывает сайт по адресу <code>/go/имя-сайта/</code>. В файле hosts строка выглядит так: <code>IP-сервера имя-сайта</code>, без <code>http://</code>. После этого сайт открывается как <code>http://имя-сайта</code>. Адрес <code>https://</code> потребует сертификат на компьютере пользователя.</p>
  </footer>
</main>
</body>
</html>
`))
