package gosttls

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"net"
	"time"
)

// Conn is a GOST TLS connection. Read and Write carry application data.
type Conn struct {
	raw        net.Conn
	in, out    *half
	pending    bytes.Buffer
	serverName string
}

type half struct {
	mac *macState
	cnt *cntStream
	seq uint64
	on  bool
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.pending.Len() > 0 {
		return c.pending.Read(p)
	}
	for {
		typ, payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch typ {
		case recordApp:
			if len(payload) == 0 {
				continue
			}
			c.pending.Write(payload)
			return c.pending.Read(p)
		case recordAlert:
			return 0, alertError(payload)
		case recordHandshake:
			// Renegotiation is not used.
			return 0, errors.New("повторное рукопожатие ГОСТ-TLS не поддерживается")
		default:
			return 0, errors.New("неожиданная TLS-запись")
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	const max = 4096
	wrote := 0
	for len(p) > 0 {
		n := len(p)
		if n > max {
			n = max
		}
		if err := c.writeRecord(recordApp, p[:n]); err != nil {
			return wrote, err
		}
		wrote += n
		p = p[n:]
	}
	return wrote, nil
}

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *Conn) writeRecord(typ byte, payload []byte) error {
	if !c.out.on {
		return writePlain(c.raw, typ, payload)
	}
	tag, err := c.out.mac.tag(c.out.seq, typ, payload)
	if err != nil {
		return err
	}
	body := make([]byte, len(payload)+len(tag))
	copy(body, payload)
	copy(body[len(payload):], tag)
	c.out.cnt.XORKeyStream(body, body)
	c.out.seq++
	return writePlain(c.raw, typ, body)
}

func (c *Conn) readRecord() (byte, []byte, error) {
	typ, payload, err := readPlain(c.raw)
	if err != nil {
		return 0, nil, err
	}
	if !c.in.on || typ == recordCCS {
		return typ, payload, nil
	}
	if len(payload) < 4 {
		return 0, nil, errors.New("короткая ГОСТ-запись")
	}
	c.in.cnt.XORKeyStream(payload, payload)
	body := payload[:len(payload)-4]
	got := payload[len(payload)-4:]
	want, err := c.in.mac.tag(c.in.seq, typ, body)
	if err != nil {
		return 0, nil, err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return 0, nil, errors.New("контрольная сумма ГОСТ-записи не сошлась")
	}
	c.in.seq++
	return typ, body, nil
}

// ServerName is the name checked in the certificate.
func (c *Conn) ServerName() string { return c.serverName }

// Ensure Conn implements net.Conn.
var _ net.Conn = (*Conn)(nil)
