package browser

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/SaaelCompany/tlswitch/internal/certs"
)

func installFromMaterial(m *certs.Material) error {
	var roots, hints [][]byte
	for _, c := range m.Certificates {
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			roots = append(roots, c.Raw)
			continue
		}
		hints = append(hints, c.Raw)
	}
	if err := writePolicy(encodeAll(roots), encodeAll(hints)); err != nil {
		if err2 := trustPlatform(roots, hints); err2 != nil {
			return fmt.Errorf("%w. %v", err, err2)
		}
	}
	return nil
}

func encodeAll(ders [][]byte) []string {
	out := make([]string, len(ders))
	for i, der := range ders {
		out[i] = base64.StdEncoding.EncodeToString(der)
	}
	return out
}
