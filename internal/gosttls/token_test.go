package gosttls

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseThumb(t *testing.T) {
	raw, err := parseThumb("aa:bb 01cc")
	if err == nil || raw != nil {
		t.Fatalf("short thumb: %v %x", err, raw)
	}
	want := bytes.Repeat([]byte{0xab}, 20)
	got, err := parseThumb("ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB ABAB")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
	if _, err := parseThumb(strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTokenRejectsBadThumb(t *testing.T) {
	_, err := LoadToken("abcd", "1234")
	if err == nil || !strings.Contains(err.Error(), "шестнадцатеричных") {
		t.Fatal(err)
	}
}

func TestLoadTokenWithoutStore(t *testing.T) {
	_, err := LoadToken(strings.Repeat("ab", 20), "")
	if err == nil {
		t.Fatal("expected an error without a token certificate")
	}
}

func TestCertificateVerifyUsesSigner(t *testing.T) {
	sig := bytes.Repeat([]byte{0x11}, 64)
	id := &Identity{Sign: func(transcript []byte) ([]byte, error) {
		if string(transcript) != "hm" {
			t.Fatalf("transcript %q", transcript)
		}
		return sig, nil
	}}
	msg, err := certificateVerify(id, []byte("hm"))
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != hsCertVerify || msg[4] != 0x08 || msg[5] != 0x40 {
		t.Fatalf("header %x", msg[:6])
	}
	if !bytes.Equal(msg[len(msg)-64:], sig) {
		t.Fatal("signature was not copied")
	}
}
