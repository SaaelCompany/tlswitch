//go:build windows

package browser

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func writePolicy(roots, hints []string) error {
	targets := []struct {
		path string
		vals []string
	}{
		{`Software\Policies\Google\Chrome\CACertificates`, roots},
		{`Software\Policies\Google\Chrome\CAHintCertificates`, hints},
		{`Software\Policies\Microsoft\Edge\CACertificates`, roots},
		{`Software\Policies\Microsoft\Edge\CAHintCertificates`, hints},
	}
	var last error
	ok := 0
	for _, t := range targets {
		if err := writeList(registry.CURRENT_USER, t.path, t.vals); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return fmt.Errorf("не удалось записать политику Chrome/Edge: %w", last)
	}
	return nil
}

func writeList(root registry.Key, path string, values []string) error {
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	for _, name := range names {
		_ = k.DeleteValue(name)
	}
	for i, v := range values {
		if err := k.SetStringValue(itoa(i+1), v); err != nil {
			return err
		}
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
