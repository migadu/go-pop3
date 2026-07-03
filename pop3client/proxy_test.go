package pop3client_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3client"
	"github.com/migadu/go-pop3/pop3server"
)

// TestProxy_HijackRelay exercises the whole proxy path end to end using only
// this library: a downstream pop3client authenticates to a front server whose
// session dials a backend with pop3client, authenticates, hijacks the
// downstream connection, and relays bytes bidirectionally. STAT/RETR/QUIT
// issued by the downstream client are served by the backend maildrop.
func TestProxy_HijackRelay(t *testing.T) {
	// Backend: real in-memory maildrop.
	backendLn := listen(t)
	store := newStore(t)
	run(t, backendLn, pop3server.Options{NewSession: store.NewSession, InsecureAuth: true})

	// Front proxy: each session relays to the backend after authenticating.
	frontLn := listen(t)
	run(t, frontLn, pop3server.Options{
		InsecureAuth: true,
		NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
			return &proxySession{conn: c, backend: backendLn.Addr().String()}, nil
		},
	})

	ctx := tctx(t)
	cl, err := pop3client.Dial(ctx, frontLn.Addr().String(), pop3client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if err := cl.AuthPlain(ctx, "", "user", "pass"); err != nil {
		t.Fatalf("downstream AuthPlain via proxy: %v", err)
	}

	// These commands are served by the backend through the relay.
	if count, _, err := cl.Stat(ctx); err != nil || count != 2 {
		t.Fatalf("STAT via proxy: count=%d err=%v", count, err)
	}
	rc, err := cl.Retr(ctx, 1)
	if err != nil {
		t.Fatalf("RETR via proxy: %v", err)
	}
	if body := readAll(t, rc); body != msg1 {
		t.Fatalf("RETR via proxy mismatch:\n got %q\nwant %q", body, msg1)
	}
	if err := cl.Quit(ctx); err != nil {
		t.Fatalf("QUIT via proxy: %v", err)
	}
}

// proxySession authenticates against a backend and then relays. All
// TRANSACTION-state methods are unreachable because the connection is hijacked
// during authentication.
type proxySession struct {
	unreachableSession
	conn    *pop3server.Conn
	backend string
}

func (p *proxySession) AuthenticateMechanisms() []string { return []string{"PLAIN"} }

func (p *proxySession) AuthenticatePlain(ctx context.Context, _identity, username, password string) error {
	return p.relayTo(ctx, username, password)
}

func (p *proxySession) Login(ctx context.Context, username, password string) error {
	return p.relayTo(ctx, username, password)
}

func (p *proxySession) relayTo(ctx context.Context, username, password string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	backend, err := pop3client.Dial(dialCtx, p.backend, pop3client.Options{})
	if err != nil {
		return &pop3server.Error{Code: "SYS/TEMP", Message: "backend unavailable", Close: true}
	}
	if err := backend.AuthPlain(dialCtx, "", username, password); err != nil {
		backend.Close()
		return &pop3server.Error{Code: "AUTH", Message: "authentication failed"}
	}

	// Take over the downstream connection (preserving any pipelined bytes).
	down, downBuf, err := p.conn.Hijack()
	if err != nil {
		backend.Close()
		return err
	}
	// The proxy owns responses now: acknowledge the successful login.
	fmt.Fprint(down, "+OK Logged in\r\n")

	relay(down, downBuf, backend)
	return nil
}

// relay copies bytes in both directions until either side closes, using
// half-close so a QUIT is delivered cleanly.
func relay(down net.Conn, downBuf io.Reader, backend *pop3client.Client) {
	up := backend.Conn()
	_ = down.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(up, downBuf) // downBuf drains buffered remainder, then the socket
		halfCloseWrite(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(down, backend.Reader()) // reader drains buffered remainder, then the socket
		halfCloseWrite(down)
		done <- struct{}{}
	}()
	<-done
	<-done
	up.Close()
	down.Close()
}

func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// unreachableSession provides pop3server.Session methods that must never be
// called (the proxy hijacks during auth). Embed it and override the auth hooks.
type unreachableSession struct{}

var errUnreachable = fmt.Errorf("proxySession: transaction method reached unexpectedly")

func (unreachableSession) Close() error                                { return nil }
func (unreachableSession) Login(context.Context, string, string) error { return errUnreachable }
func (unreachableSession) Stat(context.Context) (int, int64, error)    { return 0, 0, errUnreachable }
func (unreachableSession) List(context.Context, int) ([]pop3.MessageInfo, error) {
	return nil, errUnreachable
}
func (unreachableSession) Uidl(context.Context, int) ([]pop3.MessageUidl, error) {
	return nil, errUnreachable
}
func (unreachableSession) Retr(context.Context, int) (io.ReadCloser, error) {
	return nil, errUnreachable
}
func (unreachableSession) Top(context.Context, int, int) (io.ReadCloser, error) {
	return nil, errUnreachable
}
func (unreachableSession) Dele(context.Context, int) error   { return errUnreachable }
func (unreachableSession) Rset(context.Context) error        { return errUnreachable }
func (unreachableSession) Noop(context.Context) error        { return errUnreachable }
func (unreachableSession) Quit(context.Context) (int, error) { return 0, errUnreachable }
