package gosttls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"go.cypherpunks.ru/gogost/v5/gost3410"
)

// Identity is an organization's GOST certificate and the matching private key.
// It is sent only when a site asks for a client certificate.
type Identity struct {
	Certs []*x509.Certificate
	Key   *gost3410.PrivateKey
}

// LoadIdentity reads a PEM certificate chain and a PEM or raw GOST private key.
// The leaf is the certificate whose public key matches the private key.
func LoadIdentity(certPEM, keyPEM []byte) (*Identity, error) {
	if bytes.Contains(keyPEM, []byte("ENCRYPTED")) {
		return nil, errors.New("client_key зашифрован. Нужен файл ключа без пароля")
	}
	certs, err := parsePEMs(certPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("в client_cert нет сертификата")
	}
	key, leaf, err := matchKey(certs, keyPEM)
	if err != nil {
		return nil, err
	}
	ordered := []*x509.Certificate{leaf}
	for _, c := range certs {
		if !c.Equal(leaf) {
			ordered = append(ordered, c)
		}
	}
	return &Identity{Certs: ordered, Key: key}, nil
}

func certificateMessage(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("нет клиентского сертификата")
	}
	var list []byte
	for _, c := range certs {
		n := len(c.Raw)
		list = append(list, byte(n>>16), byte(n>>8), byte(n))
		list = append(list, c.Raw...)
	}
	body := []byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}
	body = append(body, list...)
	return handshakeMsg(hsCertificate, body), nil
}

func certificateVerify(key *gost3410.PrivateKey, transcript []byte) ([]byte, error) {
	sig, err := signTranscript(key, transcript)
	if err != nil {
		return nil, err
	}
	hashAlg := byte(0x40)
	if key.C.PointSize() == 64 {
		hashAlg = 0x41
	}
	body := []byte{0x08, hashAlg, byte(len(sig) >> 8), byte(len(sig))}
	body = append(body, sig...)
	return handshakeMsg(hsCertVerify, body), nil
}

// signTranscript produces the RFC 9189 CertificateVerify signature:
// little-endian r || little-endian s over the reversed Streebog-256 digest.
func signTranscript(key *gost3410.PrivateKey, transcript []byte) ([]byte, error) {
	sig, err := key.SignDigest(reverse(streebog(transcript)), rand.Reader)
	if err != nil {
		return nil, err
	}
	return reverse(sig), nil
}

func matchKey(certs []*x509.Certificate, keyPEM []byte) (*gost3410.PrivateKey, *x509.Certificate, error) {
	blobs := keyBlobs(keyPEM)
	if len(blobs) == 0 {
		return nil, nil, errors.New("в client_key нет закрытого ключа ГОСТ")
	}
	var last error
	for _, c := range certs {
		pub, _, err := gostPublic(c)
		if err != nil {
			last = err
			continue
		}
		for _, blob := range blobs {
			for _, priv := range privateCandidates(pub.C, blob) {
				got, err := priv.PublicKey()
				if err != nil {
					last = err
					continue
				}
				if got.X.Cmp(pub.X) == 0 && got.Y.Cmp(pub.Y) == 0 {
					return priv, c, nil
				}
			}
		}
	}
	if last != nil {
		return nil, nil, fmt.Errorf("ключ не соответствует сертификату: %w", last)
	}
	return nil, nil, errors.New("ключ не соответствует сертификату")
}

func privateCandidates(curve *gost3410.Curve, blob []byte) []*gost3410.PrivateKey {
	var out []*gost3410.PrivateKey
	size := curve.PointSize()
	try := func(raw []byte) {
		if len(raw) != size {
			return
		}
		if k, err := gost3410.NewPrivateKeyLE(curve, raw); err == nil {
			out = append(out, k)
		}
		if k, err := gost3410.NewPrivateKeyBE(curve, raw); err == nil {
			out = append(out, k)
		}
	}
	try(blob)
	for _, raw := range nestedOctets(blob) {
		try(raw)
	}
	return out
}

func keyBlobs(in []byte) [][]byte {
	if bytes.Contains(in, []byte("ENCRYPTED")) {
		return nil
	}
	var out [][]byte
	rest := in
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if strings.Contains(block.Type, "ENCRYPTED") {
			continue
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			out = append(out, block.Bytes)
		}
	}
	if sawPEM {
		return out
	}
	trimmed := bytes.TrimSpace(in)
	if decoded, err := hex.DecodeString(string(bytes.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, trimmed))); err == nil && (len(decoded) == 32 || len(decoded) == 64) {
		return [][]byte{decoded}
	}
	if len(trimmed) == 32 || len(trimmed) == 64 {
		return [][]byte{trimmed}
	}
	return nil
}

func nestedOctets(der []byte) [][]byte {
	var out [][]byte
	var walk func([]byte)
	walk = func(b []byte) {
		if len(b) == 32 || len(b) == 64 {
			out = append(out, append([]byte{}, b...))
		}
		rest := b
		for len(rest) > 0 {
			var raw asn1.RawValue
			next, err := asn1.Unmarshal(rest, &raw)
			if err != nil {
				return
			}
			if raw.Class == 0 && (raw.Tag == asn1.TagOctetString || raw.Tag == asn1.TagSequence) && len(raw.Bytes) > 0 {
				walk(raw.Bytes)
			}
			if len(next) >= len(rest) {
				return
			}
			rest = next
		}
	}
	walk(der)
	return out
}
