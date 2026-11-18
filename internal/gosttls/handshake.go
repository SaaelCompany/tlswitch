package gosttls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"go.cypherpunks.ru/gogost/v5/gost28147"
	"go.cypherpunks.ru/gogost/v5/gost3410"
	"go.cypherpunks.ru/gogost/v5/gost34112012256"
)

const (
	recordHandshake byte = 22
	recordCCS       byte = 20
	recordAlert     byte = 21
	recordApp       byte = 23

	hsClientHello     byte = 1
	hsServerHello     byte = 2
	hsCertificate     byte = 11
	hsCertRequest     byte = 13
	hsServerHelloDone byte = 14
	hsClientKeyEx     byte = 16
	hsFinished        byte = 20
)

// Handshake speaks TLS_GOSTR341112_256_WITH_28147_CNT_IMIT (RFC 9189) and
// returns a connection whose Read and Write are the protected application data.
func Handshake(ctx context.Context, raw net.Conn, serverName string, extraCerts []*x509.Certificate) (*Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	defer raw.SetDeadline(time.Time{})

	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, err
	}
	hello := clientHello(clientRandom, serverName)
	var transcript []byte
	transcript = append(transcript, hello...)
	if err := writePlain(raw, recordHandshake, hello); err != nil {
		return nil, err
	}

	var serverRandom []byte
	var certs []*x509.Certificate
	var wantClientCert bool
	for {
		typ, payload, err := readPlain(raw)
		if err != nil {
			return nil, err
		}
		if typ == recordAlert {
			return nil, alertError(payload)
		}
		if typ != recordHandshake {
			return nil, fmt.Errorf("ожидалось рукопожатие, пришло %d", typ)
		}
		msgs, err := splitHandshake(payload)
		if err != nil {
			return nil, err
		}
		done := false
		for _, m := range msgs {
			transcript = append(transcript, m.raw...)
			switch m.typ {
			case hsServerHello:
				serverRandom, err = parseServerHello(m.body)
			case hsCertificate:
				certs, err = parseCertificates(m.body)
			case hsCertRequest:
				wantClientCert = true
			case hsServerHelloDone:
				done = true
			default:
				err = fmt.Errorf("неожиданное сообщение рукопожатия %d", m.typ)
			}
			if err != nil {
				return nil, err
			}
		}
		if done {
			break
		}
	}
	if len(certs) == 0 || serverRandom == nil {
		return nil, errors.New("сервер не прислал сертификат")
	}
	if err := verifyChain(certs[0], certs[1:], extraCerts, serverName, time.Now()); err != nil {
		return nil, err
	}
	pub, algo, err := gostPublic(certs[0])
	if err != nil {
		return nil, err
	}
	ke, ps, err := clientKeyExchange(pub, algo, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}
	if wantClientCert {
		empty := []byte{hsCertificate, 0, 0, 3, 0, 0, 0}
		transcript = append(transcript, empty...)
		if err := writePlain(raw, recordHandshake, empty); err != nil {
			return nil, err
		}
		// A server that requires a user certificate aborts here, before Finished.
		_ = raw.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		var peek [7]byte
		n, perr := io.ReadFull(raw, peek[:])
		if dl, ok := ctx.Deadline(); ok {
			_ = raw.SetReadDeadline(dl)
		} else {
			_ = raw.SetReadDeadline(time.Time{})
		}
		if perr == nil || n > 0 {
			if n >= 7 && peek[0] == recordAlert {
				return nil, alertAfter(peek[5:7], true)
			}
			return nil, errors.New("сайт запросил клиентский сертификат ГОСТ и не принял подключение без него. Сертификат пользователя на шлюз не подставляется")
		}
	}
	transcript = append(transcript, ke...)
	if err := writePlain(raw, recordHandshake, ke); err != nil {
		return nil, err
	}

	ms := prf(ps, "master secret", append(append([]byte{}, clientRandom...), serverRandom...), 48)
	kb := prf(ms, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...), 144)
	outMAC, err := newMAC(kb[0:32])
	if err != nil {
		return nil, err
	}
	inMAC, err := newMAC(kb[32:64])
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		raw: raw,
		out: &half{mac: outMAC, cnt: newCNT(kb[64:96], kb[128:136])},
		in:  &half{mac: inMAC, cnt: newCNT(kb[96:128], kb[136:144])},
	}
	if err := writePlain(raw, recordCCS, []byte{1}); err != nil {
		return nil, err
	}
	conn.out.on = true
	verify := prf(ms, "client finished", streebog(transcript), 12)
	fin := make([]byte, 4+len(verify))
	fin[0] = hsFinished
	fin[3] = byte(len(verify))
	copy(fin[4:], verify)
	transcript = append(transcript, fin...)
	if err := conn.writeRecord(recordHandshake, fin); err != nil {
		return nil, err
	}

	sawCCS := false
	for !sawCCS {
		typ, payload, err := readPlain(raw)
		if err != nil {
			return nil, err
		}
		if typ == recordAlert {
			return nil, alertAfter(payload, wantClientCert)
		}
		if typ != recordCCS {
			return nil, fmt.Errorf("ожидался ChangeCipherSpec, пришло %d", typ)
		}
		sawCCS = true
	}
	conn.in.on = true
	typ, payload, err := conn.readRecord()
	if err != nil {
		return nil, err
	}
	if typ == recordAlert {
		return nil, alertAfter(payload, wantClientCert)
	}
	if typ != recordHandshake || len(payload) < 4 || payload[0] != hsFinished {
		return nil, errors.New("сервер не прислал Finished")
	}
	bodyLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if 4+bodyLen > len(payload) {
		return nil, errors.New("обрезанный Finished сервера")
	}
	got := payload[4 : 4+bodyLen]
	// The server hashes the transcript without its own Finished.
	want := prf(ms, "server finished", streebog(transcript), 12)
	if !hmac.Equal(got, want) {
		return nil, errors.New("Finished сервера не сошёлся")
	}
	conn.serverName = serverName
	return conn, nil
}

type hsMsg struct {
	typ  byte
	body []byte
	raw  []byte
}

func splitHandshake(payload []byte) ([]hsMsg, error) {
	var out []hsMsg
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, errors.New("обрезанное сообщение рукопожатия")
		}
		n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if 4+n > len(payload) {
			return nil, errors.New("обрезанное сообщение рукопожатия")
		}
		raw := payload[:4+n]
		out = append(out, hsMsg{typ: payload[0], body: payload[4 : 4+n], raw: append([]byte{}, raw...)})
		payload = payload[4+n:]
	}
	return out, nil
}

func clientHello(random []byte, serverName string) []byte {
	name := []byte(serverName)
	sniList := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(sniList[:2], uint16(1+2+len(name)))
	sniList[2] = 0
	binary.BigEndian.PutUint16(sniList[3:5], uint16(len(name)))
	copy(sniList[5:], name)
	groups := []byte{0x00, 0x22, 0x00, 0x23, 0x00, 0x24, 0x00, 0x25}
	groupData := make([]byte, 2+len(groups))
	binary.BigEndian.PutUint16(groupData[:2], uint16(len(groups)))
	copy(groupData[2:], groups)
	sigs := []byte{0x00, 0x04, 0x08, 0x40, 0x08, 0x41}
	exts := concat(
		extension(0x0000, sniList),
		extension(0x000d, sigs),
		extension(0x000a, groupData),
		extension(0xff01, []byte{0x00}),
	)
	body := make([]byte, 0, 64+len(exts))
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00) // session id
	body = append(body, 0x00, 0x02, 0xc1, 0x02)
	body = append(body, 0x01, 0x00) // null compression
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(exts)))
	body = append(body, extLen...)
	body = append(body, exts...)
	return handshakeMsg(hsClientHello, body)
}

func parseServerHello(body []byte) ([]byte, error) {
	if len(body) < 35 {
		return nil, errors.New("короткий ServerHello")
	}
	random := append([]byte{}, body[2:34]...)
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+3 > len(body) {
		return nil, errors.New("короткий ServerHello")
	}
	if body[off] != 0xc1 || body[off+1] != 0x02 {
		return nil, fmt.Errorf("сервер выбрал не ГОСТ-шифр %x", body[off:off+2])
	}
	return random, nil
}

func parseCertificates(body []byte) ([]*x509.Certificate, error) {
	if len(body) < 3 {
		return nil, errors.New("пустой список сертификатов")
	}
	rest := body[3:]
	total := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if total > len(rest) {
		return nil, errors.New("обрезанный список сертификатов")
	}
	rest = rest[:total]
	var out []*x509.Certificate
	for len(rest) > 0 {
		if len(rest) < 3 {
			return nil, errors.New("обрезанный сертификат")
		}
		n := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
		rest = rest[3:]
		if n > len(rest) {
			return nil, errors.New("обрезанный сертификат")
		}
		c, err := x509.ParseCertificate(rest[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = rest[n:]
	}
	return out, nil
}

func clientKeyExchange(peer *gost3410.PublicKey, algoDER, clientRandom, serverRandom []byte) ([]byte, []byte, error) {
	priv, err := gost3410.GenPrivateKey(peer.C, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	eph, err := priv.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	h := streebog(append(append([]byte{}, clientRandom...), serverRandom...))
	ukm := h[:8]
	// int(UKM) is little-endian (RFC 9189). KEG_28147 then diversifies with param-Z.
	ukmInt := new(big.Int).SetBytes(reverse(ukm))
	if ukmInt.Sign() == 0 {
		ukmInt = big.NewInt(1)
	}
	vko, err := priv.KEK2012256(peer, ukmInt)
	if err != nil {
		return nil, nil, err
	}
	kexp := diversify(vko, ukm)
	ps := make([]byte, 32)
	if _, err := rand.Read(ps); err != nil {
		return nil, nil, err
	}
	c := gost28147.NewCipher(kexp, &gost28147.SboxIdtc26gost28147paramZ)
	enc := make([]byte, 32)
	c.NewECBEncrypter().CryptBlocks(enc, ps)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		return nil, nil, err
	}
	if _, err := mac.Write(ps); err != nil {
		return nil, nil, err
	}
	tag := mac.Sum(nil)
	blob := keyTransport(enc, tag, ukm, algoDER, eph.Raw())
	return handshakeMsg(hsClientKeyEx, blob), ps, nil
}

func keyTransport(enc, mac, ukm, algo, point []byte) []byte {
	pointWrap := wrapPoint(point)
	spki := derSeq(concat(algo, derBitString(pointWrap)))
	// [0] IMPLICIT SubjectPublicKeyInfo replaces the SEQUENCE tag.
	eph := derTag(0xA0, spki[1+derLenSize(spki):])
	params := derTag(0xA0, concat(
		derOID([]byte{0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01}),
		eph,
		derOctet(ukm),
	))
	encKey := derSeq(concat(derOctet(enc), derOctet(mac)))
	return derSeq(derSeq(concat(encKey, params)))
}

func wrapPoint(point []byte) []byte {
	if len(point) == 64 {
		out := make([]byte, 2+len(point))
		out[0] = 0x04
		out[1] = 0x40
		copy(out[2:], point)
		return out
	}
	out := make([]byte, 3+len(point))
	out[0] = 0x04
	out[1] = 0x81
	out[2] = byte(len(point))
	copy(out[3:], point)
	return out
}

func diversify(kek, ukm []byte) []byte {
	out := append([]byte(nil), kek...)
	for i := 0; i < 8; i++ {
		var s1, s2 uint64
		for j := 0; j < 8; j++ {
			k := uint64(binary.LittleEndian.Uint32(out[j*4 : j*4+4]))
			if ukm[i]&(1<<uint(j)) != 0 {
				s1 += k
			} else {
				s2 += k
			}
		}
		iv := make([]byte, 8)
		binary.LittleEndian.PutUint32(iv[:4], uint32(s1))
		binary.LittleEndian.PutUint32(iv[4:], uint32(s2))
		c := gost28147.NewCipher(out, &gost28147.SboxIdtc26gost28147paramZ)
		c.NewCFBEncrypter(iv).XORKeyStream(out, out)
	}
	return out
}

func prf(secret []byte, label string, seed []byte, n int) []byte {
	return pHash(secret, append([]byte(label), seed...), n)
}

func pHash(secret, seed []byte, n int) []byte {
	mac := hmac.New(gost34112012256.New, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	var out []byte
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:n]
}

func streebog(b []byte) []byte {
	h := gost34112012256.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

func handshakeMsg(typ byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = typ
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

func extension(typ uint16, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(out[:2], typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(data)))
	copy(out[4:], data)
	return out
}

func writePlain(w io.Writer, typ byte, payload []byte) error {
	hdr := []byte{typ, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readPlain(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n > 1<<16 {
		return 0, nil, errors.New("слишком большая TLS-запись")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func alertError(payload []byte) error {
	return alertAfter(payload, false)
}

func alertAfter(payload []byte, clientCert bool) error {
	if clientCert && len(payload) >= 2 {
		switch payload[1] {
		case 40, 42, 48:
			return fmt.Errorf("сайт запросил клиентский сертификат ГОСТ и не принял подключение без него (alert %d). Сертификат пользователя на шлюз не подставляется", payload[1])
		}
	}
	if len(payload) >= 2 {
		return fmt.Errorf("сервер закрыл ГОСТ-TLS, alert %d", payload[1])
	}
	return errors.New("сервер закрыл ГОСТ-TLS")
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func derLenSize(der []byte) int {
	if len(der) < 2 {
		return 1
	}
	if der[1] < 0x80 {
		return 1
	}
	return 1 + int(der[1]&0x7f)
}

func derTag(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLen(len(content))...), content...)
}

func derSeq(content []byte) []byte { return derTag(0x30, content) }
func derOctet(b []byte) []byte     { return derTag(0x04, b) }
func derOID(body []byte) []byte    { return derTag(0x06, body) }

func derBitString(content []byte) []byte {
	body := append([]byte{0x00}, content...)
	return derTag(0x03, body)
}
