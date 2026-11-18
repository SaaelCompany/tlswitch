package gosttls

import (
	"encoding/binary"

	"go.cypherpunks.ru/gogost/v5/gost28147"
)

// meshConst is the CryptoPro key meshing constant from RFC 4357.
var meshConst = []byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// cntStream is GOST 28147-89 in CryptoPro CNT mode with key meshing
// (RFC 9189 CNT_IMIT, param-Z).
type cntStream struct {
	c     *gost28147.Cipher
	iv    [8]byte
	count int
	gamma [8]byte
	used  int
}

func newCNT(key, iv []byte) *cntStream {
	s := &cntStream{
		c:    gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ),
		used: 8,
	}
	copy(s.iv[:], iv)
	return s
}

func (s *cntStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if s.used == 8 {
			s.next()
			s.used = 0
		}
		dst[i] = src[i] ^ s.gamma[s.used]
		s.used++
	}
}

func (s *cntStream) next() {
	if s.count == 1024 {
		s.mesh()
	}
	var block [8]byte
	if s.count == 0 {
		s.c.Encrypt(block[:], s.iv[:])
	} else {
		copy(block[:], s.iv[:])
	}
	g0 := uint32(block[0]) | uint32(block[1])<<8 | uint32(block[2])<<16 | uint32(block[3])<<24
	g0 += 0x01010101
	block[0] = byte(g0)
	block[1] = byte(g0 >> 8)
	block[2] = byte(g0 >> 16)
	block[3] = byte(g0 >> 24)
	go1 := uint32(block[4]) | uint32(block[5])<<8 | uint32(block[6])<<16 | uint32(block[7])<<24
	g1 := go1 + 0x01010104
	if go1 > g1 {
		g1++
	}
	block[4] = byte(g1)
	block[5] = byte(g1 >> 8)
	block[6] = byte(g1 >> 16)
	block[7] = byte(g1 >> 24)
	copy(s.iv[:], block[:])
	s.c.Encrypt(s.gamma[:], block[:])
	s.count = s.count%1024 + 8
}

func (s *cntStream) mesh() {
	newKey := make([]byte, 32)
	s.c.NewECBDecrypter().CryptBlocks(newKey, meshConst)
	s.c = gost28147.NewCipher(newKey, &gost28147.SboxIdtc26gost28147paramZ)
	var niv [8]byte
	s.c.Encrypt(niv[:], s.iv[:])
	copy(s.iv[:], niv[:])
}

// macState is the running gostIMIT28147 (4-byte tag, zero IV) over every
// record of one direction. RFC 9189 feeds STR_8(seq)|type|version|length|fragment
// of all records so far into one CBC-MAC.
type macState struct {
	m *gost28147.MAC
}

func newMAC(key []byte) (*macState, error) {
	c := gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)
	m, err := c.NewMAC(4, make([]byte, 8))
	if err != nil {
		return nil, err
	}
	return &macState{m: m}, nil
}

func (m *macState) tag(seq uint64, typ byte, payload []byte) ([]byte, error) {
	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[:8], seq)
	hdr[8] = typ
	hdr[9] = 0x03
	hdr[10] = 0x03
	binary.BigEndian.PutUint16(hdr[11:13], uint16(len(payload)))
	if _, err := m.m.Write(hdr[:]); err != nil {
		return nil, err
	}
	if _, err := m.m.Write(payload); err != nil {
		return nil, err
	}
	// Sum mixes the unfinished block into a copy. The running MAC must keep
	// that block for the next record.
	return m.m.Clone().Sum(nil), nil
}
