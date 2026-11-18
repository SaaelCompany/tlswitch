package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SaaelCompany/tlswitch/internal/certs"
)

func TestCollapseTransferEncoding(t *testing.T) {
	in := []byte("HTTP/1.1 200 OK\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n")
	got := collapseTransferEncoding(in)
	want := []byte("HTTP/1.1 200 OK\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	same := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	if !bytes.Equal(collapseTransferEncoding(same), same) {
		t.Fatal("rewrote a single chunked header")
	}
	joined := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n")
	if !bytes.Equal(collapseTransferEncoding(joined), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")) {
		t.Fatalf("joined: %q", collapseTransferEncoding(joined))
	}
}

func TestReadResponseDuplicateTE(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n\r\n\r\nbye!" +
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"3;ext=1\r\nbye\r\n0\r\nX-Foo: bar\r\n\r\n"
	if _, err := http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(raw))), nil); err == nil || !strings.Contains(err.Error(), `too many transfer encodings`) {
		t.Fatalf("fixture should be rejected, got %v", err)
	}

	a, b := pipeWithDeadline(t)
	go func() {
		_, _ = io.WriteString(a, raw)
		_ = a.Close()
	}()
	br := bufio.NewReader(wrapResponse(oneByteConn{b}))
	body := readBody(t, br, nil)
	if body != "hello" {
		t.Fatalf("body %q", body)
	}
	body = readBody(t, br, nil)
	if body != "\r\n\r\nbye!" {
		t.Fatalf("second %q", body)
	}
	body = readBody(t, br, nil)
	if body != "bye" {
		t.Fatalf("third %q", body)
	}
}

func TestKeepAliveHEADAndPOST(t *testing.T) {
	server, client := pipeWithDeadline(t)
	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		steps := []struct {
			method string
			reply  string
		}{
			{"POST", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"},
			{"HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"},
			{"GET", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye"},
		}
		for _, step := range steps {
			req, err := http.ReadRequest(br)
			if err != nil {
				errCh <- err
				return
			}
			got, _ := io.ReadAll(req.Body)
			req.Body.Close()
			if req.Method != step.method {
				errCh <- errString("method " + req.Method)
				return
			}
			if step.method == "POST" && string(got) != "abc" {
				errCh <- errString("post body " + string(got))
				return
			}
			if _, err := io.WriteString(server, step.reply); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return wrapResponse(client), nil
		},
		DisableCompression: true,
	}
	hc := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	post, err := http.NewRequest(http.MethodPost, "http://gisoms.ffoms.gov.ru/p", strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := hc.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "hello" {
		t.Fatalf("post body %q", body)
	}
	head, err := http.NewRequest(http.MethodHead, "http://gisoms.ffoms.gov.ru/h", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err = hc.Do(head)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.ContentLength != 4 {
		t.Fatalf("head %d len %d", res.StatusCode, res.ContentLength)
	}
	res, err = hc.Get("http://gisoms.ffoms.gov.ru/g")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "bye" {
		t.Fatalf("get %q", body)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestTransportDuplicateTE(t *testing.T) {
	ca, caPEM, leaf := testCA(t, "example.com")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				for i := 0; i < 2; i++ {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
					var raw string
					if i == 0 {
						raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
					} else {
						raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nbye"
					}
					if _, err := io.WriteString(c, raw); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tr, err := NewFromMaterial(&certs.Material{Roots: roots, Certificates: []*x509.Certificate{ca}}, Options{
		AllowPrivate: true,
		Override:     map[string]string{"example.com:443": ln.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	res, err := hc.Get("https://example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "hello" || res.StatusCode != 200 {
		t.Fatalf("first %d %q", res.StatusCode, body)
	}
	res, err = hc.Get("https://example.com/b")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "bye" {
		t.Fatalf("second %q", body)
	}
}

func readBody(t *testing.T, br *bufio.Reader, req *http.Request) string {
	t.Helper()
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pipeWithDeadline(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	d := time.Now().Add(3 * time.Second)
	_ = a.SetDeadline(d)
	_ = b.SetDeadline(d)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

type oneByteConn struct{ net.Conn }

func (c oneByteConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.Conn.Read(p[:1])
}

type errString string

func (e errString) Error() string { return string(e) }
