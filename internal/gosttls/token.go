package gosttls

import (
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
)

// parseThumb accepts the certificate thumbprint shown by Windows certmgr
// (SHA-1, 40 hex digits) or a 64-digit SHA-256 / Streebog-256 fingerprint.
// Spaces and colons are ignored.
func parseThumb(s string) ([]byte, error) {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == ':' {
			continue
		}
		b.WriteRune(r)
	}
	raw, err := hex.DecodeString(b.String())
	if err != nil || (len(raw) != 20 && len(raw) != 32) {
		return nil, errors.New("upstream.client_thumbprint должен быть отпечатком сертификата: 40 или 64 шестнадцатеричных знака")
	}
	return raw, nil
}

// Thumbprint returns the canonical hex form when s is a certificate thumbprint.
func Thumbprint(s string) (string, bool) {
	raw, err := parseThumb(s)
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(raw), true
}
