// Package certs holds the public Russian Trusted CA certificates published
// for government TLS. They are embedded so each workstation does not need them.
package certs

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// Official distribution: https://www.gosuslugi.ru/crt and gu-st.ru.
//
//go:embed russian_trusted_root_ca.pem
var rootPEM []byte

//go:embed russian_trusted_sub_ca.pem
var subPEM []byte

//go:embed russian_trusted_sub_ca_2024.pem
var sub2024PEM []byte

// SHA256 fingerprints of the embedded certificates (DER), so a replaced file
// is obvious in tests and in the admin guide.
const (
	RootFingerprint    = "D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31"
	SubFingerprint     = "BBBDE2103E790B999EC62BD03CF625A5A2E7C316E10AFE6A490EEDEAD8B3FD9B"
	Sub2024Fingerprint = "2155785036C900DBB5F1BB2A1569C80C55595BD6BF94867A29BBDDBC7D88A3F2"
)

// Material is the parsed trust material used for upstream TLS.
type Material struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	Certificates  []*x509.Certificate
}

// Load parses the embedded certificates and any extra PEM the admin supplied.
// Self-signed certificates are roots. Everything else is an intermediate.
func Load(extraPEM []byte) (*Material, error) {
	all := append([]byte{}, rootPEM...)
	all = append(all, '\n')
	all = append(all, subPEM...)
	all = append(all, '\n')
	all = append(all, sub2024PEM...)
	if len(extraPEM) > 0 {
		all = append(all, '\n')
		all = append(all, extraPEM...)
	}
	parsed, err := parsePEM(all)
	if err != nil {
		return nil, err
	}
	if len(parsed) < 3 {
		return nil, fmt.Errorf("во встроенном наборе меньше трёх сертификатов")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range parsed {
		if c.Subject.String() == c.Issuer.String() {
			roots.AddCert(c)
			continue
		}
		inter.AddCert(c)
	}
	return &Material{Roots: roots, Intermediates: inter, Certificates: parsed}, nil
}

// DERCertificates returns every embedded and extra certificate as DER.
func DERCertificates(extraPEM []byte) ([][]byte, error) {
	m, err := Load(extraPEM)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(m.Certificates))
	for i, c := range m.Certificates {
		out[i] = c.Raw
	}
	return out, nil
}

func parsePEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("сертификат: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("в PEM нет сертификатов")
	}
	return out, nil
}

// Fingerprint is the SHA-256 of the certificate DER, hex-encoded uppercase.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	const hexdigits = "0123456789ABCDEF"
	buf := make([]byte, 64)
	for i, b := range sum {
		buf[i*2] = hexdigits[b>>4]
		buf[i*2+1] = hexdigits[b&0x0f]
	}
	return string(buf)
}
