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
func TestRFC9189MasterSecret(t *testing.T) {
	cr := hx("6A523D6880DCC2DC75CCC43CFD04B616F5C3757B8077B76A9B504949FD3BFDB8")
	sr := hx("FE92C9516D0E1A67A04C33CD7F2C90B15E76DCC30815C19F92A6D100915AF2DB")
	ps := hx("CE0DD6B6704212152BE4695A7E89F64C8929A40DBF0A5A55C2CE002B06BAB62F")
	want := hx("BE5746C8BBB7847E978FD4C94F523452442C8EB172FDE6281C18C54463B1F94C2BD9814005416DBB0F90A57EA4E06B50")
	got := prf(ps, "master secret", append(append([]byte{}, cr...), sr...), 48)
	if !bytesEq(got, want) {
		t.Fatalf("MS %x", got)
	}
	kb := prf(got, "key expansion", append(append([]byte{}, sr...), cr...), 144)
	wantKB := hx("F337F6A86FF31FCA52EA647CDEE3B78334AB77B57FE0DB2FC0C871ECDCACA5A8FBA04C2132823A2496EF936F0EBCF30EA0CB7EAF6CA794754F1F45B17722DEB44E5BC32D4430AF5893116ACF81A3BE0C90D2EA8E76E0840728BAF5E2B2F940C0AE18267BB634C16A1D1AC1247350954B2FEE9B77F30D18D554012B437860870AD921A84B07FF98AF8C82386B91FBBA64")
	if !bytesEq(kb, wantKB) {
		t.Fatalf("KB %x", kb)
	}
}

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
