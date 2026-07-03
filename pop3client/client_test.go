package pop3client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3client"
	"github.com/migadu/go-pop3/pop3mem"
	"github.com/migadu/go-pop3/pop3server"
)

const (
	// msg1 deliberately contains a line beginning with '.' to exercise
	// dot-stuffing on the server and unstuffing on the client.
	msg1 = "Subject: one\r\nFrom: a@example.com\r\n\r\nHello world\r\n.leading dot\r\ntail\r\n"
	msg2 = "Subject: two\r\n\r\nsecond message body\r\n"
)

func newStore(t *testing.T) *pop3mem.Store {
	t.Helper()
	s := pop3mem.New()
	s.AddUser("user", "pass")
	if err := s.AddMessage("user", "uid-1", []byte(msg1)); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMessage("user", "uid-2", []byte(msg2)); err != nil {
		t.Fatal(err)
	}
	return s
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func run(t *testing.T, ln net.Listener, opts pop3server.Options) {
	t.Helper()
	srv := pop3server.New(opts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

func tctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// testTLS returns a matched (server, client) TLS config using a fresh
// self-signed certificate for 127.0.0.1.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return &tls.Config{Certificates: []tls.Certificate{cert}},
		&tls.Config{InsecureSkipVerify: true}
}

func TestClient_FeatureRoundTrip(t *testing.T) {
	ln := listen(t)
	store := newStore(t)
	run(t, ln, pop3server.Options{NewSession: store.NewSession, InsecureAuth: true})

	ctx := tctx(t)
	cl, err := pop3client.Dial(ctx, ln.Addr().String(), pop3client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if !strings.HasPrefix(cl.Greeting(), "+OK") {
		t.Fatalf("greeting: %q", cl.Greeting())
	}

	caps, err := cl.Capa(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !containsPrefix(caps, "UIDL") || !containsPrefix(caps, "TOP") || !containsPrefix(caps, "SASL") {
		t.Fatalf("CAPA missing expected capabilities: %v", caps)
	}

	if err := cl.AuthPlain(ctx, "", "user", "pass"); err != nil {
		t.Fatalf("AuthPlain: %v", err)
	}

	// STAT
	count, size, err := cl.Stat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantSize := int64(len(msg1) + len(msg2))
	if count != 2 || size != wantSize {
		t.Fatalf("STAT: got %d/%d, want 2/%d", count, size, wantSize)
	}

	// LIST all + single
	list, err := cl.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Size != int64(len(msg1)) || list[1].Size != int64(len(msg2)) {
		t.Fatalf("LIST: %+v", list)
	}
	if one, err := cl.ListOne(ctx, 2); err != nil || one.Num != 2 || one.Size != int64(len(msg2)) {
		t.Fatalf("LIST 2: %+v err=%v", one, err)
	}

	// UIDL all + single
	uidl, err := cl.Uidl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(uidl) != 2 || uidl[0].UniqueID != "uid-1" || uidl[1].UniqueID != "uid-2" {
		t.Fatalf("UIDL: %+v", uidl)
	}
	if one, err := cl.UidlOne(ctx, 1); err != nil || one.UniqueID != "uid-1" {
		t.Fatalf("UIDL 1: %+v err=%v", one, err)
	}

	// RETR — full body must survive dot-stuffing round trip exactly.
	rc, err := cl.Retr(ctx, 1)
	if err != nil {
		t.Fatalf("RETR 1: %v", err)
	}
	if body := readAll(t, rc); body != msg1 {
		t.Fatalf("RETR 1 body mismatch:\n got %q\nwant %q", body, msg1)
	}

	// TOP with 0 body lines — headers + blank line only.
	trc, err := cl.Top(ctx, 1, 0)
	if err != nil {
		t.Fatalf("TOP 1 0: %v", err)
	}
	if top := readAll(t, trc); top != "Subject: one\r\nFrom: a@example.com\r\n\r\n" {
		t.Fatalf("TOP 1 0: got %q", top)
	}

	// DELE 1 then STAT reflects the deletion.
	if err := cl.Dele(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if count, _, _ := cl.Stat(ctx); count != 1 {
		t.Fatalf("STAT after DELE: count=%d, want 1", count)
	}

	// RSET restores it.
	if err := cl.Rset(ctx); err != nil {
		t.Fatal(err)
	}
	if count, _, _ := cl.Stat(ctx); count != 2 {
		t.Fatalf("STAT after RSET: count=%d, want 2", count)
	}

	if err := cl.Noop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cl.Quit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestClient_ImplicitTLS(t *testing.T) {
	tlsRoundTrip(t, false)
}

func TestClient_STARTTLS(t *testing.T) {
	tlsRoundTrip(t, true)
}

func tlsRoundTrip(t *testing.T, starttls bool) {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	store := newStore(t)

	ln := listen(t)
	opts := pop3server.Options{NewSession: store.NewSession, TLSConfig: serverTLS}
	if !starttls {
		// Implicit TLS: wrap the listener; connections are TLS from byte one.
		ln = tls.NewListener(ln, serverTLS)
	}
	run(t, ln, opts)

	ctx := tctx(t)
	cl, err := pop3client.Dial(ctx, ln.Addr().String(), pop3client.Options{
		TLSConfig: clientTLS,
		STARTTLS:  starttls,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	// Auth is only permitted because the connection is TLS (no InsecureAuth).
	if err := cl.AuthPlain(ctx, "", "user", "pass"); err != nil {
		t.Fatalf("AuthPlain over TLS (starttls=%v): %v", starttls, err)
	}
	if count, _, err := cl.Stat(ctx); err != nil || count != 2 {
		t.Fatalf("STAT over TLS: count=%d err=%v", count, err)
	}
	if err := cl.Quit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestClient_XClientForwarding(t *testing.T) {
	store := newStore(t)

	var mu sync.Mutex
	var gotArgs []string

	ln := listen(t)
	run(t, ln, pop3server.Options{
		NewSession:   store.NewSession,
		InsecureAuth: true,
		UnknownCommandHandler: func(_ context.Context, c *pop3server.Conn, cmd string, args []string) (bool, bool) {
			if cmd != "XCLIENT" {
				return false, false
			}
			mu.Lock()
			gotArgs = args
			mu.Unlock()
			c.OK("XCLIENT accepted")
			return true, false
		},
	})

	ctx := tctx(t)
	cl, err := pop3client.Dial(ctx, ln.Addr().String(), pop3client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if err := cl.XClient(ctx,
		pop3client.XClientParam{Name: "ADDR", Value: "203.0.113.7"},
		pop3client.XClientParam{Name: "LOGIN", Value: "user@example.com"},
	); err != nil {
		t.Fatalf("XClient: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotArgs) != 2 || gotArgs[0] != "ADDR=203.0.113.7" || gotArgs[1] != "LOGIN=user@example.com" {
		t.Fatalf("server received XCLIENT args %v", gotArgs)
	}
}

// --- helpers ---

func containsPrefix(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
