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
	// Server Finished uses the read half of the same key block.
	inMAC, err := newMAC(km[32:64])
	if err != nil {
		t.Fatal(err)
	}
	inCNT := newCNT(km[96:128], km[136:144])
	serverWire, _ := hex.DecodeString("7BDDBB3C0A6A4A9E302B468CCD5CF786665FFEBC")
	inCNT.XORKeyStream(serverWire, serverWire)
	body = serverWire[:len(serverWire)-4]
	gotTag := serverWire[len(serverWire)-4:]
	wantTag, err := inMAC.tag(0, 0x16, body)
	if err != nil {
		t.Fatal(err)
	}
	wantPlain, _ := hex.DecodeString("1400000CD6A2A697E9F23DB0F9017A79")
	if !bytes.Equal(body, wantPlain) || !bytes.Equal(gotTag, wantTag) {
		t.Fatalf("server finished\n plain %x\n tag %x want %x", body, gotTag, wantTag)
	}
	app = []byte("HELO\n")
	serverApp, _ := hex.DecodeString("0F368E5CEC86B4F8D7")
	inCNT.XORKeyStream(serverApp, serverApp)
	body = serverApp[:len(serverApp)-4]
	gotTag = serverApp[len(serverApp)-4:]
	wantTag, err = inMAC.tag(1, 0x17, body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, app) || !bytes.Equal(gotTag, wantTag) {
		t.Fatalf("server app\n plain %x\n tag %x want %x", body, gotTag, wantTag)
	}
}

func TestRecordRoundTripCrossesKeyMesh(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 8)
	macKey := bytes.Repeat([]byte{0x33}, 32)
	plain := bytes.Repeat([]byte("gost"), 400) // 1600 bytes, past the 1024-byte mesh
	outMAC, err := newMAC(macKey)
	if err != nil {
		t.Fatal(err)
	}
	out := newCNT(key, iv)
	tag, err := outMAC.tag(0, 0x17, plain)
	if err != nil {
		t.Fatal(err)
	}
	body := append(append([]byte{}, plain...), tag...)
	enc := make([]byte, len(body))
	out.XORKeyStream(enc, body)

	inMAC, err := newMAC(macKey)
	if err != nil {
		t.Fatal(err)
	}
	in := newCNT(key, iv)
	in.XORKeyStream(enc, enc)
	got := enc[:len(enc)-4]
	sum, err := inMAC.tag(0, 0x17, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) || !bytes.Equal(enc[len(enc)-4:], sum) {
		t.Fatal("meshed record did not round-trip")
	}
}
