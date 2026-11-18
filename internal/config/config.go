// Package config loads tlswitch.yaml.
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration.
type Config struct {
	Listen       string   `yaml:"listen"`
	TLSListen    string   `yaml:"tls_listen"`
	TLSCert      string   `yaml:"tls_cert"`
	TLSKey       string   `yaml:"tls_key"`
	AuthUser     string   `yaml:"auth_user"`
	AuthPassword string   `yaml:"auth_password"`
	AllowClients []string `yaml:"allow_clients"`

	AllowSuffixes []string     `yaml:"allow_suffixes"`
	Portal        []PortalSite `yaml:"portal"`
	Upstream      Upstream     `yaml:"upstream"`
	Browser       Browser      `yaml:"browser"`
	DataDir       string       `yaml:"data_dir"`
}

// PortalSite is one entry on the start page.
type PortalSite struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
	Note  string `yaml:"note"`
}

// Upstream is how the gateway connects to government sites.
type Upstream struct {
	MinTLS           string   `yaml:"min_tls"`
	DNS              []string `yaml:"dns"`
	CAFile           string   `yaml:"ca_file"`
	ClientCert       string   `yaml:"client_cert"`
	ClientKey        string   `yaml:"client_key"`
	ClientThumbprint string   `yaml:"client_thumbprint"`
	ClientPin        string   `yaml:"client_pin"`
	Proxy            string   `yaml:"proxy"`
	AllowPrivate     bool     `yaml:"allow_private"`
}

// Browser is the server-side Chrome/Edge session used when a real login is required.
type Browser struct {
	Enabled     bool   `yaml:"enabled"`
	Path        string `yaml:"path"`
	NoSandbox   bool   `yaml:"no_sandbox"`
	MaxSessions int    `yaml:"max_sessions"`
	IdleTimeout string `yaml:"idle_timeout"`
	Quality     int    `yaml:"quality"`
	MaxWidth    int    `yaml:"max_width"`
	MaxHeight   int    `yaml:"max_height"`
}

// File is a loaded config plus derived values.
type File struct {
	Config
	ClientNets  []*net.IPNet
	IdleTimeout time.Duration
	ExtraCA     []byte
}

// Load reads a YAML file and fills defaults.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("конфигурация %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("конфигурация %s: %w", path, err)
	}
	return prepare(cfg)
}

func prepare(cfg Config) (*File, error) {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:80"
	}
	if _, err := net.ResolveTCPAddr("tcp", cfg.Listen); err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if cfg.TLSListen != "" {
		if _, err := net.ResolveTCPAddr("tcp", cfg.TLSListen); err != nil {
			return nil, fmt.Errorf("tls_listen: %w", err)
		}
		if cfg.TLSCert == "" || cfg.TLSKey == "" {
			return nil, fmt.Errorf("для tls_listen нужны tls_cert и tls_key")
		}
	}
	if len(cfg.AllowSuffixes) == 0 {
		cfg.AllowSuffixes = DefaultSuffixes()
	} else {
		// An already installed tlswitch.yaml lists suffixes by name. New
		// built-in suffixes are added so replacing only the program is enough.
		have := map[string]bool{}
		for _, s := range cfg.AllowSuffixes {
			have[s] = true
		}
		for _, s := range DefaultSuffixes() {
			if !have[s] {
				cfg.AllowSuffixes = append(cfg.AllowSuffixes, s)
			}
		}
	}
	if len(cfg.Portal) == 0 {
		cfg.Portal = DefaultPortal()
	}
	if cfg.Upstream.MinTLS == "" {
		cfg.Upstream.MinTLS = "1.2"
	}
	switch cfg.Upstream.MinTLS {
	case "1.0", "1.1", "1.2", "1.3":
	default:
		return nil, fmt.Errorf("upstream.min_tls должен быть 1.0, 1.1, 1.2 или 1.3")
	}
	if len(cfg.Upstream.DNS) == 0 {
		cfg.Upstream.DNS = []string{"77.88.8.8:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	for i, d := range cfg.Upstream.DNS {
		if _, _, err := net.SplitHostPort(d); err != nil {
			cfg.Upstream.DNS[i] = net.JoinHostPort(d, "53")
		}
	}
	if cfg.Browser.MaxSessions <= 0 {
		cfg.Browser.MaxSessions = 4
	}
	if cfg.Browser.Quality <= 0 || cfg.Browser.Quality > 100 {
		cfg.Browser.Quality = 70
	}
	if cfg.Browser.MaxWidth <= 0 {
		cfg.Browser.MaxWidth = 1600
	}
	if cfg.Browser.MaxHeight <= 0 {
		cfg.Browser.MaxHeight = 1200
	}
	idle := 20 * time.Minute
	if cfg.Browser.IdleTimeout != "" {
		d, err := time.ParseDuration(cfg.Browser.IdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("browser.idle_timeout: %w", err)
		}
		idle = d
	}
	var nets []*net.IPNet
	for _, c := range cfg.AllowClients {
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("allow_clients %q: %w", c, err)
		}
		nets = append(nets, n)
	}
	f := &File{Config: cfg, ClientNets: nets, IdleTimeout: idle}
	if cfg.Upstream.CAFile != "" {
		b, err := os.ReadFile(cfg.Upstream.CAFile)
		if err != nil {
			return nil, fmt.Errorf("upstream.ca_file: %w", err)
		}
		f.ExtraCA = b
	}
	return f, nil
}

// DefaultSuffixes are the public suffixes of Russian government sites and the
// Gosuslugi static host. This is an allowlist, not an open proxy.
func DefaultSuffixes() []string {
	return []string{
		"gosuslugi.ru",
		"xn--c1aapkosapc.xn--p1ai", // госуслуги.рф
		"gu-st.ru",
		"nalog.ru",
		"nalog.gov.ru",
		"government.ru",
		"gov.ru",
		"rosminzdrav.ru",
		"mos.ru",
		"cbr.ru",
		"rosreestr.ru",
		"rosreestr.gov.ru",
		"sfr.gov.ru",
		"pfr.gov.ru",
		"fssp.gov.ru",
		"xn--b1aew.xn--p1ai",   // мвд.рф
		"xn--90adear.xn--p1ai", // гибдд.рф
	}
}

// DefaultPortal is the start page when the config does not list sites.
func DefaultPortal() []PortalSite {
	return []PortalSite{
		{Title: "Госуслуги", URL: "https://www.gosuslugi.ru", Note: "Заявление, запись, личный кабинет"},
		{Title: "ЕСИА", URL: "https://esia.gosuslugi.ru/login/", Note: "Вход в государственные системы"},
		{Title: "ГИС ОМС", URL: "https://gisoms.ffoms.gov.ru", Note: "Федеральный фонд ОМС. Нужен сертификат организации с токена: upstream.client_thumbprint"},
		{Title: "ФРМО", URL: "https://nr.egisz.rosminzdrav.ru", Note: "Реестр медицинских организаций"},
		{Title: "ФРМР", URL: "https://portalmr.egisz.rosminzdrav.ru", Note: "Регистр медицинских работников"},
		{Title: "Налог.ру", URL: "https://www.nalog.gov.ru", Note: "Федеральная налоговая служба"},
		{Title: "Личный кабинет налогоплательщика", URL: "https://lkfl2.nalog.ru", Note: "Налоги физического лица"},
		{Title: "Мой налог", URL: "https://lknpd.nalog.ru", Note: "Самозанятые"},
		{Title: "Мос.ру", URL: "https://www.mos.ru", Note: "Услуги города Москвы"},
		{Title: "Банк России", URL: "https://www.cbr.ru", Note: "Сайт Банка России"},
		{Title: "Росреестр", URL: "https://rosreestr.gov.ru", Note: "Недвижимость и кадастр"},
		{Title: "Социальный фонд", URL: "https://sfr.gov.ru", Note: "Пенсии и пособия"},
		{Title: "ФССП", URL: "https://fssp.gov.ru", Note: "Судебные приставы"},
		{Title: "Правительство России", URL: "https://government.ru", Note: "Документы и постановления"},
		{Title: "Минцифры", URL: "https://digital.gov.ru", Note: "Министерство цифрового развития"},
		{Title: "Закупки", URL: "https://zakupki.gov.ru", Note: "Единая информационная система закупок"},
		{Title: "МВД", URL: "https://мвд.рф", Note: "Министерство внутренних дел"},
		{Title: "ГИБДД", URL: "https://гибдд.рф", Note: "Штрафы и регистрация автомобилей"},
	}
}
