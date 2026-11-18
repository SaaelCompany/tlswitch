package gosttls

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"time"

	"go.cypherpunks.ru/gogost/v5/gost3410"
	"go.cypherpunks.ru/gogost/v5/gost34112012256"
)

// verifyChain checks that leaf is a currently valid certificate for serverName
// and that each GOST signature leads to an embedded trust anchor.
func verifyChain(leaf *x509.Certificate, presented []*x509.Certificate, extra []*x509.Certificate, serverName string, now time.Time) error {
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("срок сертификата %s истёк или ещё не наступил", serverName)
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("имя %s отсутствует в сертификате", serverName)
	}
	anchors := append([]*x509.Certificate{}, trustAnchors()...)
	var intermediates []*x509.Certificate
	for _, c := range append(append([]*x509.Certificate{}, presented...), extra...) {
		if c == nil || c.Equal(leaf) {
			continue
		}
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			anchors = append(anchors, c)
			continue
		}
		intermediates = append(intermediates, c)
	}
	intermediates = append(intermediates, extraIntermediates()...)
	current := leaf
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		if bytes.Equal(current.RawSubject, current.RawIssuer) {
			if !trusted(current, anchors) {
				return fmt.Errorf("корневой сертификат %s не входит в доверенные", current.Subject.CommonName)
			}
			if err := verifyGOST(current, current); err != nil {
				return err
			}
			return nil
		}
		parent := findIssuer(current, append(intermediates, anchors...))
		if parent == nil {
			return fmt.Errorf("нет сертификата издателя для %s", current.Subject.CommonName)
		}
		key := string(parent.Raw)
		if seen[key] {
			return fmt.Errorf("цикл в цепочке сертификата %s", serverName)
		}
		seen[key] = true
		if err := verifyGOST(current, parent); err != nil {
			return err
		}
		if now.Before(parent.NotBefore) || now.After(parent.NotAfter) {
			return fmt.Errorf("срок сертификата издателя %s истёк", parent.Subject.CommonName)
		}
		current = parent
	}
	return fmt.Errorf("слишком длинная цепочка сертификата %s", serverName)
}

func trusted(c *x509.Certificate, anchors []*x509.Certificate) bool {
	for _, a := range anchors {
		if a.Equal(c) || bytes.Equal(a.Raw, c.Raw) {
			return true
		}
	}
	return false
}

func findIssuer(child *x509.Certificate, pool []*x509.Certificate) *x509.Certificate {
	for _, c := range pool {
		if bytes.Equal(c.RawSubject, child.RawIssuer) {
			return c
		}
	}
	return nil
}

// verifyGOST checks parent signed child. The digest is little-endian;
// the signature bytes are already in the order VerifyDigest expects.
func verifyGOST(child, parent *x509.Certificate) error {
	pub, _, err := gostPublic(parent)
	if err != nil {
		return fmt.Errorf("ключ издателя %s: %w", parent.Subject.CommonName, err)
	}
	sum := gost34112012256.New()
	_, _ = sum.Write(child.RawTBSCertificate)
	digest := sum.Sum(nil)
	for i, j := 0, len(digest)-1; i < j; i, j = i+1, j-1 {
		digest[i], digest[j] = digest[j], digest[i]
	}
	ok, err := pub.VerifyDigest(digest, child.Signature)
	if err != nil {
		return fmt.Errorf("подпись %s: %w", child.Subject.CommonName, err)
	}
	if !ok {
		return fmt.Errorf("подпись сертификата %s не сходится", child.Subject.CommonName)
	}
	return nil
}

func gostPublic(c *x509.Certificate) (*gost3410.PublicKey, []byte, error) {
	var spki struct {
		Algo asn1.RawValue
		Bits asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, err
	}
	raw, err := pointBytes(spki.Bits.Bytes)
	if err != nil {
		return nil, nil, err
	}
	curve := curveFromDER(spki.Algo.FullBytes)
	if curve == nil {
		return nil, nil, fmt.Errorf("неизвестная кривая ГОСТ")
	}
	pub, err := gost3410.NewPublicKey(curve, raw)
	if err != nil {
		return nil, nil, err
	}
	return pub, spki.Algo.FullBytes, nil
}

func pointBytes(b []byte) ([]byte, error) {
	// BIT STRING payload is an OCTET STRING of the raw point: 04 40 || 64, or 04 81 80 || 128.
	if len(b) >= 2 && b[0] == 0x04 && b[1] == 0x40 && len(b) >= 2+64 {
		return b[2 : 2+64], nil
	}
	if len(b) >= 3 && b[0] == 0x04 && b[1] == 0x81 && b[2] == 0x80 && len(b) >= 3+128 {
		return b[3 : 3+128], nil
	}
	if len(b) == 64 || len(b) == 128 {
		return b, nil
	}
	return nil, fmt.Errorf("непонятный открытый ключ ГОСТ (%d байт)", len(b))
}

func curveFromDER(der []byte) *gost3410.Curve {
	switch {
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00}):
		return gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01}):
		return gost3410.CurveIdGostR34102001CryptoProAParamSet()
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02}):
		return gost3410.CurveIdGostR34102001CryptoProBParamSet()
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03}):
		return gost3410.CurveIdGostR34102001CryptoProCParamSet()
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01}):
		return gost3410.CurveIdtc26gost341012256paramSetA()
	case bytes.Contains(der, []byte{0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01}):
		return gost3410.CurveIdtc26gost341012512paramSetA()
	default:
		return nil
	}
}

func parsePEMs(pems ...[]byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, block := range pems {
		rest := block
		for len(rest) > 0 {
			var p *pem.Block
			p, rest = pem.Decode(rest)
			if p == nil {
				break
			}
			if p.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(p.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}
