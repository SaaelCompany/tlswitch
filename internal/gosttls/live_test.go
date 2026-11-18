package gosttls

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedChain(t *testing.T) {
	roots := trustAnchors()
	subs := extraIntermediates()
	if len(roots) != 1 || len(subs) != 1 {
		t.Fatalf("anchors root %d sub %d err %v", len(roots), len(subs), anchorErr)
	}
	if err := verifyGOST(subs[0], roots[0]); err != nil {
		t.Fatal(err)
	}
	if err := verifyGOST(roots[0], roots[0]); err != nil {
		t.Fatal(err)
	}
}

func TestLiveGIS(t *testing.T) {
	if os.Getenv("GOST_LIVE") != "1" {
		t.Skip("set GOST_LIVE=1 to dial gisoms.ffoms.gov.ru")
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	raw, err := d.DialContext(ctx, "tcp", "gisoms.ffoms.gov.ru:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, err := Handshake(ctx, raw, "gisoms.ffoms.gov.ru", nil, nil)
	if err == nil {
		defer conn.Close()
		req := "GET / HTTP/1.0\r\nHost: gisoms.ffoms.gov.ru\r\nConnection: close\r\n\r\n"
		_, _ = io.WriteString(conn, req)
		buf := make([]byte, 200)
		n, _ := conn.Read(buf)
		t.Fatalf("expected client-certificate refusal, got %q", buf[:n])
	}
	if !strings.Contains(err.Error(), "клиентский сертификат") {
		t.Fatal(err)
	}
}
