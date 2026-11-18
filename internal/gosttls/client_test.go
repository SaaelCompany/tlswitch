package gosttls

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"go.cypherpunks.ru/gogost/v5/gost3410"
)

func TestRFCClientSignature(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	d := mustHex(t, "0918AD3F7D209ABF89F1E8505DA894CEE10DA09D32E72E815D9C0ADA30B5A103")
	q := mustHex(t, "0F5DB18A9E15F324B778676025BFD7B5DF066566EABAA1C51CD879F87B0B49759EE5BBF18361F842D3F087DEC2943939E0FA2BFB4EDEC25A8D10ABB22C48F386")
	hash := mustHex(t, "9D640DD8B2546B8705CC3E67F3BB832F892A5BD5D45CA044850114C2E6560269")
	sig := mustHex(t, "F71F4362455BC55BA89A8FAF018288EC00B32717482E7624B257D9797C8FF602E315FDBD8DE56D085418040E1B61BBF6B301AC263D50038B303113DB3617503A")
	priv, err := gost3410.NewPrivateKeyBE(curve, d)
	if err != nil {
		t.Fatal(err)
	}
	want, err := gost3410.NewPublicKeyBE(curve, q)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := want.VerifyDigest(reverse(hash), reverse(sig))
	if err != nil || !ok {
		t.Fatalf("RFC signature did not verify: %v %v", ok, err)
	}
	wire, err := signTranscript(priv, []byte("handshake"))
	if err != nil {
		t.Fatal(err)
	}
	sum := reverse(streebog([]byte("handshake")))
	ok, err = want.VerifyDigest(sum, reverse(wire))
	if err != nil || !ok {
		t.Fatalf("round trip: %v %v", ok, err)
	}
}

func TestLoadIdentityMatchesKey(t *testing.T) {
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	raw := mustHex(t, "0918AD3F7D209ABF89F1E8505DA894CEE10DA09D32E72E815D9C0ADA30B5A103")
	priv, err := gost3410.NewPrivateKeyBE(curve, raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := selfSignedGOST(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8GOST(raw)})
	id, err := LoadIdentity(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Certs[0].Equal(cert) {
		t.Fatal("leaf was not kept")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pkcs8GOST(raw []byte) []byte {
	inner, _ := asn1.Marshal(raw)
	algo := struct {
		OID    asn1.ObjectIdentifier
		Params asn1.ObjectIdentifier
	}{
		OID:    asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1},
		Params: asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1},
	}
	info := struct {
		Version int
		Algo    any
		Key     []byte
	}{Algo: algo, Key: inner}
	der, err := asn1.Marshal(info)
	if err != nil {
		panic(err)
	}
	return der
}

func selfSignedGOST(pub *gost3410.PublicKey) (*x509.Certificate, error) {
	point := append([]byte{0x04, 0x40}, pub.RawLE()...)
	spki := struct {
		Algo struct {
			OID    asn1.ObjectIdentifier
			Params asn1.ObjectIdentifier
		}
		Bits asn1.BitString
	}{
		Bits: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	}
	spki.Algo.OID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	spki.Algo.Params = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	spkiDER, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}
	name := pkixName("org")
	validity, err := asn1.Marshal(struct {
		NotBefore, NotAfter time.Time
	}{time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		return nil, err
	}
	algo, err := asn1.Marshal(struct {
		OID asn1.ObjectIdentifier
	}{asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}})
	if err != nil {
		return nil, err
	}
	tbs, err := asn1.Marshal(struct {
		Version int `asn1:"tag:0,explicit"`
		Serial  *big.Int
		Algo    asn1.RawValue
		Name    asn1.RawValue
		Valid   asn1.RawValue
		Subject asn1.RawValue
		SPKI    asn1.RawValue
	}{
		Version: 2, Serial: big.NewInt(1),
		Algo:    asn1.RawValue{FullBytes: algo},
		Name:    asn1.RawValue{FullBytes: name},
		Valid:   asn1.RawValue{FullBytes: validity},
		Subject: asn1.RawValue{FullBytes: name},
		SPKI:    asn1.RawValue{FullBytes: spkiDER},
	})
	if err != nil {
		return nil, err
	}
	// The signature is not checked by ParseCertificate.
	certDER, err := asn1.Marshal(struct {
		TBS  asn1.RawValue
		Algo asn1.RawValue
		Sig  asn1.BitString
	}{
		TBS:  asn1.RawValue{FullBytes: tbs},
		Algo: asn1.RawValue{FullBytes: algo},
		Sig:  asn1.BitString{Bytes: []byte{0}, BitLength: 8},
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func pkixName(cn string) []byte {
	der, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: mustRDN(cn)})
	if err != nil {
		panic(err)
	}
	return der
}

func mustRDN(cn string) []byte {
	attr, err := asn1.Marshal(struct {
		OID asn1.ObjectIdentifier
		CN  string `asn1:"utf8"`
	}{OID: asn1.ObjectIdentifier{2, 5, 4, 3}, CN: cn})
	if err != nil {
		panic(err)
	}
	set, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSet, IsCompound: true, Bytes: attr})
	if err != nil {
		panic(err)
	}
	return set
}
