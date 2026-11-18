package gosttls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC9189Records(t *testing.T) {
	km, _ := hex.DecodeString("F337F6A86FF31FCA52EA647CDEE3B78334AB77B57FE0DB2FC0C871ECDCACA5A8FBA04C2132823A2496EF936F0EBCF30EA0CB7EAF6CA794754F1F45B17722DEB44E5BC32D4430AF5893116ACF81A3BE0C90D2EA8E76E0840728BAF5E2B2F940C0AE18267BB634C16A1D1AC1247350954B2FEE9B77F30D18D554012B437860870AD921A84B07FF98AF8C82386B91FBBA64")
	if len(km) != 144 {
		t.Fatalf("key material %d", len(km))
	}
	mac, err := newMAC(km[0:32])
	if err != nil {
		t.Fatal(err)
	}
	cnt := newCNT(km[64:96], km[128:136])
	fin, _ := hex.DecodeString("1400000CD3EE1DEA725CD7080C744311")
	tag, err := mac.tag(0, 0x16, fin)
	if err != nil {
		t.Fatal(err)
	}
	body := append(append([]byte{}, fin...), tag...)
	out := make([]byte, len(body))
	cnt.XORKeyStream(out, body)
	want, _ := hex.DecodeString("8854A0ED0CCBDAE076FA7D22D763A8D1AF701BBB")
	if !bytes.Equal(out, want) {
		t.Fatalf("finished ciphertext\n got %x\nwant %x", out, want)
	}
	app := []byte("HELO\n")
	tag, err = mac.tag(1, 0x17, app)
	if err != nil {
		t.Fatal(err)
	}
	body = append(append([]byte{}, app...), tag...)
	out = make([]byte, len(body))
	cnt.XORKeyStream(out, body)
	want, _ = hex.DecodeString("A8951D9389D1AEFE3B")
	if !bytes.Equal(out, want) {
		t.Fatalf("app ciphertext\n got %x\nwant %x", out, want)
	}
}
