package certs

import "testing"

func TestEmbeddedFingerprints(t *testing.T) {
	m, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Certificates) != 3 {
		t.Fatalf("certs: got %d", len(m.Certificates))
	}
	got := map[string]bool{}
	for _, c := range m.Certificates {
		got[Fingerprint(c)] = true
		t.Log(c.Subject.CommonName, Fingerprint(c))
	}
	for _, want := range []string{RootFingerprint, SubFingerprint, Sub2024Fingerprint} {
		if !got[want] {
			t.Errorf("missing fingerprint %s", want)
		}
	}
	if m.Roots == nil || m.Intermediates == nil {
		t.Fatal("pools are nil")
	}
}
