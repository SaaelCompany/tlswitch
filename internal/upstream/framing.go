package upstream

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

// ГИС ОМС (и часть прокси перед ним) пишет Transfer-Encoding: chunked
// двумя строками на одно и то же тело. net/http рвёт такое соединение:
// "too many transfer encodings". Заголовок схлопывается здесь, пока
// клиент его не разобрал. Границы тела запоминаются, чтобы следующий
// ответ на том же соединении тоже прошёл через схлопывание: иначе
// bufio клиента заберёт сырой заголовок вперёд и правка уже не поможет.

var loggedDupTE sync.Once

func wrapResponse(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	return &responseConn{Conn: c}
}

type responseConn struct {
	net.Conn
	mu     sync.Mutex
	method string

	phase      int
	left       int64
	acc        []byte
	out        []byte
	chunk      chunkState
	pendingErr error
	scratch    []byte

	reqPhase int
	reqLeft  int64
	reqAcc   []byte
	reqChunk chunkState
}

const (
	phaseHeader = iota
	phaseBody
	phaseChunk
	phaseUntilClose
)

const (
	reqHeader = iota
	reqBody
	reqChunk
	reqIgnore
)

type reqSave struct {
	phase  int
	left   int64
	acc    []byte
	chunk  chunkState
	method string
}

func (c *responseConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	saved := c.saveReq()
	c.noteWrite(p)
	c.mu.Unlock()

	n, err := c.Conn.Write(p)
	if n != len(p) {
		c.mu.Lock()
		c.restoreReq(saved)
		if n > 0 {
			c.noteWrite(p[:n])
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *responseConn) saveReq() reqSave {
	return reqSave{
		phase:  c.reqPhase,
		left:   c.reqLeft,
		acc:    append([]byte(nil), c.reqAcc...),
		chunk:  c.reqChunk.clone(),
		method: c.method,
	}
}

func (c *responseConn) restoreReq(s reqSave) {
	c.reqPhase = s.phase
	c.reqLeft = s.left
	c.reqAcc = s.acc
	c.reqChunk = s.chunk
	c.method = s.method
}

func (c *responseConn) currentMethod() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method
}

func (c *responseConn) noteWrite(p []byte) {
	for len(p) > 0 {
		switch c.reqPhase {
		case reqHeader:
			if i := bytes.Index(p, []byte("\r\n\r\n")); i >= 0 && len(c.reqAcc) == 0 {
				head := p[:i]
				p = p[i+4:]
				c.finishReqHeader(head)
				continue
			}
			c.reqAcc = append(c.reqAcc, p...)
			p = nil
			if i := bytes.Index(c.reqAcc, []byte("\r\n\r\n")); i >= 0 {
				head := append([]byte(nil), c.reqAcc[:i]...)
				rest := append([]byte(nil), c.reqAcc[i+4:]...)
				c.reqAcc = nil
				c.finishReqHeader(head)
				p = rest
			} else if len(c.reqAcc) > 1<<20 {
				c.reqAcc = nil
				c.reqPhase = reqIgnore
			}
		case reqBody:
			if c.reqLeft <= 0 {
				c.reqPhase = reqHeader
				continue
			}
			if int64(len(p)) > c.reqLeft {
				p = p[c.reqLeft:]
				c.reqLeft = 0
				c.reqPhase = reqHeader
				continue
			}
			c.reqLeft -= int64(len(p))
			if c.reqLeft == 0 {
				c.reqPhase = reqHeader
			}
			return
		case reqChunk:
			n, done, bad := c.reqChunk.feed(p)
			if bad || n == 0 {
				c.reqPhase = reqIgnore
				return
			}
			p = p[n:]
			if done {
				c.reqChunk = chunkState{}
				c.reqPhase = reqHeader
			}
		default:
			return
		}
	}
}

func (c *responseConn) finishReqHeader(head []byte) {
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) > 0 {
		if f := bytes.Fields(lines[0]); len(f) > 0 {
			c.method = string(f[0])
		}
	}
	var te, cl string
	for _, line := range lines[1:] {
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, "Transfer-Encoding"):
			te = value
		case strings.EqualFold(name, "Content-Length"):
			cl = value
		}
	}
	if tokensHaveChunked(te) {
		c.reqPhase = reqChunk
		c.reqChunk = chunkState{}
		return
	}
	n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
	if err != nil || n <= 0 {
		c.reqPhase = reqHeader
		c.reqLeft = 0
		return
	}
	c.reqPhase = reqBody
	c.reqLeft = n
}

func (c *responseConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.pump()
		if n := c.pull(p); n > 0 {
			return n, nil
		}
		if c.pendingErr != nil {
			if c.phase == phaseHeader && len(c.acc) > 0 {
				c.out = append(c.out, c.acc...)
				c.acc = nil
			}
			if n := c.pull(p); n > 0 {
				return n, nil
			}
			err := c.pendingErr
			c.pendingErr = nil
			return 0, err
		}
		if c.phase == phaseUntilClose {
			return c.Conn.Read(p)
		}
		if len(c.acc) > 1<<20 {
			return 0, errors.New("слишком большой заголовок ответа")
		}
		if c.scratch == nil {
			c.scratch = make([]byte, 32<<10)
		}
		n, err := c.Conn.Read(c.scratch)
		if n > 0 {
			c.acc = append(c.acc, c.scratch[:n]...)
		}
		if err != nil {
			c.pendingErr = err
			continue
		}
		if n == 0 {
			return 0, nil
		}
	}
}

func (c *responseConn) pull(p []byte) int {
	if len(c.out) == 0 {
		return 0
	}
	n := copy(p, c.out)
	c.out = c.out[n:]
	if len(c.out) == 0 {
		c.out = nil
	}
	return n
}

func (c *responseConn) pump() {
	for {
		switch c.phase {
		case phaseHeader:
			i := bytes.Index(c.acc, []byte("\r\n\r\n"))
			if i < 0 {
				return
			}
			raw := append([]byte(nil), c.acc[:i+4]...)
			rest := append([]byte(nil), c.acc[i+4:]...)
			c.acc = rest
			if !bytes.HasPrefix(raw, []byte("HTTP/")) {
				c.out = append(c.out, raw...)
				c.out = append(c.out, c.acc...)
				c.acc = nil
				c.phase = phaseUntilClose
				return
			}
			fixed := collapseTransferEncoding(raw)
			if !bytes.Equal(fixed, raw) {
				loggedDupTE.Do(func() {
					log.Printf("ответ с повторным Transfer-Encoding приведён к одному chunked")
				})
			}
			c.out = append(c.out, fixed...)
			switch next, n := classifyResponse(fixed, c.currentMethod()); next {
			case phaseBody:
				c.phase = phaseBody
				c.left = n
			case phaseChunk:
				c.phase = phaseChunk
				c.chunk = chunkState{}
			case phaseUntilClose:
				c.phase = phaseUntilClose
				c.out = append(c.out, c.acc...)
				c.acc = nil
				return
			default:
				c.phase = phaseHeader
			}
		case phaseBody:
			if c.left <= 0 {
				c.phase = phaseHeader
				continue
			}
			if len(c.acc) == 0 {
				return
			}
			take := int64(len(c.acc))
			if take > c.left {
				take = c.left
			}
			c.out = append(c.out, c.acc[:take]...)
			c.acc = append([]byte(nil), c.acc[take:]...)
			c.left -= take
			if c.left == 0 {
				c.phase = phaseHeader
				continue
			}
			return
		case phaseChunk:
			if len(c.acc) == 0 {
				return
			}
			n, done, bad := c.chunk.feed(c.acc)
			if n > 0 {
				c.out = append(c.out, c.acc[:n]...)
				c.acc = append([]byte(nil), c.acc[n:]...)
			}
			if bad || (n == 0 && !done) {
				c.phase = phaseUntilClose
				c.out = append(c.out, c.acc...)
				c.acc = nil
				return
			}
			if done {
				c.phase = phaseHeader
				c.chunk = chunkState{}
				continue
			}
			return
		default:
			return
		}
	}
}

func classifyResponse(head []byte, method string) (int, int64) {
	lines := bytes.Split(head, []byte("\r\n"))
	status := 0
	if len(lines) > 0 {
		if f := bytes.Fields(lines[0]); len(f) >= 2 {
			status, _ = strconv.Atoi(string(f[1]))
		}
	}
	// 101 — дальше не HTTP, а выбранный протокол.
	if status == 101 {
		return phaseUntilClose, 0
	}
	if strings.EqualFold(method, "HEAD") || status/100 == 1 || status == 204 || status == 304 {
		return phaseHeader, 0
	}
	var te []string
	var cl string
	for _, line := range lines[1:] {
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, "Transfer-Encoding"):
			te = append(te, headerTokens(value)...)
		case strings.EqualFold(name, "Content-Length") && cl == "":
			cl = strings.TrimSpace(value)
		}
	}
	if tokensHaveChunked(strings.Join(te, ",")) {
		return phaseChunk, 0
	}
	if cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return phaseUntilClose, 0
		}
		if n == 0 {
			return phaseHeader, 0
		}
		return phaseBody, n
	}
	return phaseUntilClose, 0
}

func collapseTransferEncoding(head []byte) []byte {
	if !bytes.HasPrefix(head, []byte("HTTP/")) {
		return head
	}
	lines := bytes.Split(head, []byte("\r\n"))
	var kept [][]byte
	var tokens []string
	teLines := 0
	for i, line := range lines {
		if i == 0 || len(line) == 0 {
			kept = append(kept, line)
			continue
		}
		name, value, ok := splitHeader(line)
		if !ok || !strings.EqualFold(name, "Transfer-Encoding") {
			kept = append(kept, line)
			continue
		}
		teLines++
		tokens = append(tokens, headerTokens(value)...)
	}
	if teLines == 0 {
		return head
	}
	chunked := false
	var other []string
	seen := map[string]bool{}
	for _, token := range tokens {
		key := strings.ToLower(token)
		if key == "identity" || seen[key] {
			continue
		}
		seen[key] = true
		if key == "chunked" {
			chunked = true
			continue
		}
		other = append(other, token)
	}
	if teLines == 1 && chunked && len(other) == 0 && len(tokens) == 1 {
		return head
	}
	te := ""
	if chunked {
		// net/http принимает только одно значение и только "chunked".
		te = "chunked"
	} else if len(other) == 1 {
		te = other[0]
	}
	var b bytes.Buffer
	inserted := false
	for i, line := range kept {
		if !inserted && len(line) == 0 {
			if te != "" {
				b.WriteString("Transfer-Encoding: ")
				b.WriteString(te)
				b.WriteString("\r\n")
			}
			inserted = true
		}
		b.Write(line)
		if i != len(kept)-1 {
			b.WriteString("\r\n")
		}
	}
	return b.Bytes()
}

func splitHeader(line []byte) (name, value string, ok bool) {
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return "", "", false
	}
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	return string(line[:i]), strings.TrimSpace(string(line[i+1:])), true
}

func headerTokens(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func tokensHaveChunked(value string) bool {
	for _, token := range headerTokens(value) {
		if strings.EqualFold(token, "chunked") {
			return true
		}
	}
	return false
}

const (
	chunkSize = iota
	chunkData
	chunkCRLF
	chunkTrailer
)

type chunkState struct {
	step  int
	left  int64
	cr    int
	line  []byte
	trail []byte
}

func (s chunkState) clone() chunkState {
	s.line = append([]byte(nil), s.line...)
	s.trail = append([]byte(nil), s.trail...)
	return s
}

func (s *chunkState) feed(b []byte) (n int, done bool, bad bool) {
	for n < len(b) {
		switch s.step {
		case chunkSize:
			s.line = append(s.line, b[n])
			n++
			if s.line[len(s.line)-1] != '\n' {
				if len(s.line) > 4096 {
					return n, false, true
				}
				continue
			}
			sz, err := parseChunkSize(s.line)
			s.line = s.line[:0]
			if err != nil || sz < 0 {
				return n, false, true
			}
			if sz == 0 {
				s.step = chunkTrailer
				s.trail = nil
			} else {
				s.left = sz
				s.step = chunkData
			}
		case chunkData:
			have := int64(len(b) - n)
			if have > s.left {
				have = s.left
			}
			n += int(have)
			s.left -= have
			if s.left == 0 {
				s.step = chunkCRLF
				s.cr = 0
			}
		case chunkCRLF:
			n++
			s.cr++
			if s.cr >= 2 {
				s.step = chunkSize
			}
		case chunkTrailer:
			s.trail = append(s.trail, b[n])
			n++
			if bytes.Equal(s.trail, []byte("\r\n")) || bytes.HasSuffix(s.trail, []byte("\r\n\r\n")) {
				return n, true, false
			}
			if len(s.trail) > 1<<20 {
				return n, false, true
			}
		default:
			return n, false, true
		}
	}
	return n, false, false
}

func parseChunkSize(line []byte) (int64, error) {
	line = bytes.TrimRight(line, "\r\n")
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return 0, errors.New("пустой размер блока")
	}
	return strconv.ParseInt(string(line), 16, 64)
}
