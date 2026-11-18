package gosttls

import (
	"encoding/hex"
	"math/big"
	"testing"

	"go.cypherpunks.ru/gogost/v5/gost28147"
	"go.cypherpunks.ru/gogost/v5/gost3410"
)

// RFC 9189 appendix A.2 CNT_IMIT: VKO_256 equals the published K_EXP, and
// param-Z CryptoPro diversification of that key produces CEK_ENC and CEK_MAC.
func TestRFC9189KExp(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012512paramSetA()
	rawD := hx("C96486B1A3732389A162F5AD0145D53743C9AC27D42ACF1091CE7EF67E6C3CCA0F6C879B2DA3C1607648BAEB96471BD2078DF5CAAA4FA83ECC0FFD6D3C8E5D56")
	q := hx("9567949F6ABFA3D9891C7021F289FD24141B84E3232924B858913855467954E07A9B2E9D85AC2E0B993E43D5136AF3976D23244899434120C88A27C06605DB16CFD40FA0C47720086DA01516764404228232F7F7F226986280DAFFAA99BB6F7D5AE64A5A28CB02FDB84FE20DD57AAEA53516BB2BF1856BBCC823BDC5DE801ED0")
	pub, err := gost3410.NewPublicKeyLE(curve, q)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := gost3410.NewPrivateKeyBE(curve, rawD)
	if err != nil {
		t.Fatal(err)
	}
	ukm := hx("FBF39D10E800AF70")
	vko, err := priv.KEK2012256(pub, new(big.Int).SetBytes(reverse(ukm)))
	if err != nil {
		t.Fatal(err)
	}
	wantK := hx("3FD999D1684A15CC9BDD5A35067AF69817150022E09554AC791A60F161F55349")
	if !bytesEq(vko, wantK) {
		t.Fatalf("VKO %x", vko)
	}
	k := diversify(vko, ukm)
	ps := hx("CE0DD6B6704212152BE4695A7E89F64C8929A40DBF0A5A55C2CE002B06BAB62F")
	wantEnc := hx("D622D167A5642E29525A295CB9F28F96F28B0EFAA7D3A2BEE149B01178C2DFD5")
	wantMac := hx("4C933657")
	c := gost28147.NewCipher(k, &gost28147.SboxIdtc26gost28147paramZ)
	enc := make([]byte, 32)
	c.NewECBEncrypter().CryptBlocks(enc, ps)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = mac.Write(ps)
	if !bytesEq(enc, wantEnc) || !bytesEq(mac.Sum(nil), wantMac) {
		t.Fatalf("enc %x mac %x", enc, mac.Sum(nil))
	}
}

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
