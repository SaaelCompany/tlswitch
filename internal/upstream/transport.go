// Package upstream dials government sites.
//
// Name resolution uses the configured public resolvers, so a split DNS that
// points those names at this gateway does not make the gateway dial itself.
// Private, loopback and link-local answers are refused.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SaaelCompany/tlswitch/internal/certs"
	"github.com/SaaelCompany/tlswitch/internal/gosttls"
)

// Transport is an HTTP client transport for upstream government sites.
type Transport struct {
	base *http.Transport
}

// Options configures upstream connections.
type Options struct {
	MinTLS       uint16
	Roots        *x509.CertPool
	DNS          []string
	Proxy        string
	AllowPrivate bool
	// Client is presented when a GOST site asks for a client certificate.
	Client *gosttls.Identity
	// Override replaces a dial address "host:port". Tests point a name at a local server.
	Override map[string]string
	Timeout  time.Duration
}

// NewFromMaterial builds a transport that verifies the site certificate
// against the system roots plus the Russian Trusted CA set.
// HTTP/2 is off: several older government stacks mishandle it.
func NewFromMaterial(m *certs.Material, opt Options) (*Transport, error) {
	if m == nil || m.Roots == nil {
		return nil, errors.New("нет хранилища корневых сертификатов")
	}
	var intermediates []*x509.Certificate
	for _, c := range m.Certificates {
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			continue
		}
		intermediates = append(intermediates, c)
	}
	return newTransport(opt, m.Roots, intermediates)
}

func newTransport(opt Options, roots *x509.CertPool, intermediates []*x509.Certificate) (*Transport, error) {
	if roots == nil {
		return nil, errors.New("нет хранилища корневых сертификатов")
	}
	if opt.MinTLS == 0 {
		opt.MinTLS = tls.VersionTLS12
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	d := &dialer{
		dns:          append([]string{}, opt.DNS...),
		allowPrivate: opt.AllowPrivate,
		override:     opt.Override,
		timeout:      opt.Timeout,
	}
	extra := append([]*x509.Certificate{}, intermediates...)
	tlsConf := &tls.Config{
		MinVersion: opt.MinTLS,
		// Verification is performed in VerifyConnection. InsecureSkipVerify
		// only skips the default check so that missing intermediates can be
		// supplied from the embedded set. The callback rejects anything that
		// does not chain to a trusted root for this exact hostname.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyChain(cs, roots, extra)
		},
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	base := &http.Transport{
		DialContext: d.DialContext,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialTLS(ctx, d, tlsConf, extra, opt.Client, network, address)
		},
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   opt.Timeout,
		ResponseHeaderTimeout: 45 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableCompression:    false,
	}
	if opt.Proxy != "" {
		u, err := url.Parse(opt.Proxy)
		if err != nil {
			return nil, fmt.Errorf("upstream.proxy: %w", err)
		}
		base.Proxy = http.ProxyURL(u)
	}
	return &Transport{base: base}, nil
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r)
}

// CloseIdleConnections closes idle sockets.
func (t *Transport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}

func dialTLS(ctx context.Context, d *dialer, tlsConf *tls.Config, extra []*x509.Certificate, client *gosttls.Identity, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	raw, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conf := tlsConf.Clone()
	conf.ServerName = host
	tlsConn := tls.Client(raw, conf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isCertError(err) {
			return nil, err
		}
		raw, dialErr := d.DialContext(ctx, network, address)
		if dialErr != nil {
			return nil, err
		}
		gconn, gerr := gosttls.Handshake(ctx, raw, host, extra, client)
		if gerr != nil {
			_ = raw.Close()
			if gostAnswer(gerr) {
				return nil, gerr
			}
			return nil, err
		}
		return gconn, nil
	}
	return tlsConn, nil
}

func isCertError(err error) bool {
	var unk x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var inv x509.CertificateInvalidError
	var sys x509.SystemRootsError
	return errors.As(err, &unk) || errors.As(err, &hostErr) || errors.As(err, &inv) || errors.As(err, &sys)
}

func gostAnswer(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "клиентский сертификат") ||
		strings.Contains(msg, "сертификат") ||
		strings.Contains(msg, "ГОСТ-TLS") ||
		strings.Contains(msg, "Finished")
}

func verifyChain(cs tls.ConnectionState, roots *x509.CertPool, extra []*x509.Certificate) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("сервер не прислал сертификат")
	}
	if cs.ServerName == "" {
		return errors.New("пустое имя сервера в TLS")
	}
	pool := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	for _, c := range extra {
		pool.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Roots:         roots,
		Intermediates: pool,
	}
	if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type dialer struct {
	dns          []string
	allowPrivate bool
	override     map[string]string
	timeout      time.Duration
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if repl, ok := d.override[net.JoinHostPort(host, port)]; ok {
		address = repl
		host, port, err = net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
	}
	ips, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	ips = publicOnly(ips, d.allowPrivate)
	if len(ips) == 0 {
		return nil, fmt.Errorf("имя %s указывает на внутренний или локальный адрес, соединение остановлено", host)
	}
	var last error
	nd := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	for _, ip := range ips {
		c, err := nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("нет адреса для %s", host)
	}
	return nil, last
}

func (d *dialer) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	var last error
	for _, server := range d.dns {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "udp", server)
			},
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := r.LookupIP(lookupCtx, "ip", host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		last = err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	if err != nil {
		return nil, err
	}
	if last != nil {
		return nil, last
	}
	return nil, fmt.Errorf("имя %s не резолвится", host)
}

func publicOnly(ips []net.IP, allowPrivate bool) []net.IP {
	if allowPrivate {
		return ips
	}
	var out []net.IP
	for _, ip := range ips {
		if !isPrivate(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func isPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Carrier-grade NAT, 100.64.0.0/10, and link-local / metadata 169.254.0.0/16.
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}
