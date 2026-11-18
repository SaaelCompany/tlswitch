//go:build !windows

package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func trustPlatform(roots, hints [][]byte) error {
	return errors.New("хранилище сертификатов ОС здесь не используется")
}

func writePolicy(roots, hints []string) error {
	doc := map[string]any{}
	if len(roots) > 0 {
		doc["CACertificates"] = roots
	}
	if len(hints) > 0 {
		doc["CAHintCertificates"] = hints
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dirs := []string{
		"/etc/opt/chrome/policies/managed",
		"/etc/chromium/policies/managed",
		"/etc/opt/edge/policies/managed",
	}
	var last error
	wrote := 0
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			last = err
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "tlswitch.json"), raw, 0o644); err != nil {
			last = err
			continue
		}
		wrote++
	}
	if wrote == 0 {
		return fmt.Errorf("Chrome не получил сертификаты Минцифры: %v. Запустите службу от администратора или создайте /etc/opt/chrome/policies/managed", last)
	}
	return nil
}
