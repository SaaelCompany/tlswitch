//go:build !windows

package gosttls

import "errors"

// LoadToken reads a certificate installed from a hardware token.
// The private key stays on the token. That path uses CryptoPro CSP and
// exists only in the Windows build.
func LoadToken(thumb, pin string) (*Identity, error) {
	if _, err := parseThumb(thumb); err != nil {
		return nil, err
	}
	_ = pin
	return nil, errors.New("сертификат с токена доступен в сборке Windows с КриптоПро CSP")
}
