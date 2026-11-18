package gosttls

import (
	"bytes"
	"testing"
)

func TestClientHelloCarriesCryptoProAlgorithms(t *testing.T) {
	hello := clientHello(bytes.Repeat([]byte{1}, 32), "lk.zakupki.gov.ru")
	if !bytes.Contains(hello, []byte{0xee, 0xee, 0x08, 0x40, 0xef, 0xef, 0x08, 0x41, 0xed, 0xed}) {
		t.Fatalf("missing CryptoPro signature algorithms: %x", hello)
	}
	if !bytes.Contains(hello, []byte{0xc1, 0x02}) {
		t.Fatalf("missing CNT_IMIT: %x", hello)
	}
	var buf bytes.Buffer
	if err := writeHello(&buf, hello); err != nil {
		t.Fatal(err)
	}
	rec := buf.Bytes()
	if len(rec) < 3 || rec[0] != recordHandshake || rec[1] != 0x03 || rec[2] != 0x01 {
		t.Fatalf("client hello record: %x", rec[:5])
	}
}
