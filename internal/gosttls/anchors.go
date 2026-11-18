package gosttls

import (
	"crypto/x509"
	_ "embed"
	"sync"
)

// Head CA of the Ministry of Digital Development (ГУЦ 2022) and the Federal
// Treasury intermediate that signs gisoms.ffoms.gov.ru. Both are public.

//go:embed guc2022.pem
var gucPEM []byte

//go:embed ucfk2025.pem
var ucfkPEM []byte

var (
	anchorOnce sync.Once
	anchorRoot []*x509.Certificate
	anchorSub  []*x509.Certificate
	anchorErr  error
)

func loadAnchors() {
	anchorOnce.Do(func() {
		all, err := parsePEMs(gucPEM, ucfkPEM)
		if err != nil {
			anchorErr = err
			return
		}
		for _, c := range all {
			if c.RawSubject != nil && string(c.RawSubject) == string(c.RawIssuer) {
				anchorRoot = append(anchorRoot, c)
				continue
			}
			anchorSub = append(anchorSub, c)
		}
	})
}

func trustAnchors() []*x509.Certificate {
	loadAnchors()
	return anchorRoot
}

func extraIntermediates() []*x509.Certificate {
	loadAnchors()
	return anchorSub
}
