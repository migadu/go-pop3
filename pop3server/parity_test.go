package pop3server_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// A failed PASS keeps the username, so a client may retry with a bare PASS
// without re-sending USER (RFC 1939 permits either behavior; retaining
// matches common server practice).
func TestServer_FailedLoginRetainsUsername(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    5,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS wrong")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("expected auth failure, got %q", resp)
	}
	writeLine(t, conn, "PASS pass")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("bare PASS retry after failure should succeed, got %q", resp)
	}
}

// By default failed logins count toward MaxErrors and disconnect the client
// when the budget is exhausted.
func TestServer_FailedLoginsCountByDefault(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    2,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS wrong")
	mustLine(t, r)
	writeLine(t, conn, "PASS wrong")
	mustLine(t, r)
	if !drainForTooMany(r) {
		t.Fatal("expected 'Too many errors' + close after 2 failed logins")
	}
}

// With AuthFailuresExemptFromMaxErrors, failed logins never disconnect the
// session (an external rate limiter is assumed), while protocol errors still
// count.
func TestServer_AuthFailuresExemptFromMaxErrors(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth:                    true,
		MaxErrors:                       2,
		AuthFailuresExemptFromMaxErrors: true,
		IdleTimeout:                     5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	for i := 0; i < 4; i++ {
		writeLine(t, conn, "PASS wrong")
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d: expected auth failure, got %q", i, resp)
		}
	}
	writeLine(t, conn, "PASS pass")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("connection should have survived exempted failures, got %q", resp)
	}
}

// An over-long command line gets a courtesy "-ERR Line too long" before the
// connection is dropped (the oversized line cannot be drained safely).
func TestServer_LineTooLongResponse(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER "+strings.Repeat("a", 3000))
	resp, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("expected -ERR before close, got read error %v", err)
	}
	if !strings.Contains(resp, "Line too long") {
		t.Fatalf("got %q, want 'Line too long'", resp)
	}
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("connection should be closed after over-long line")
	}
}

// badListSession violates the Session contract by answering a single-message
// LIST/UIDL query with zero items and no error.
type badListSession struct{ *mockSession }

func (s *badListSession) List(ctx context.Context, msg int) ([]pop3.MessageInfo, error) {
	if msg > 0 {
		return nil, nil
	}
	return s.mockSession.List(ctx, msg)
}

func (s *badListSession) Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error) {
	if msg > 0 {
		return []pop3.MessageUidl{}, nil
	}
	return s.mockSession.Uidl(ctx, msg)
}

// A single-message LIST/UIDL query must never receive a multi-line response:
// when the session breaks the exactly-one-item contract, the library fails
// closed with a single -ERR line and the connection stays usable.
func TestServer_SingleMessageListContractViolation(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &badListSession{newMockSession()}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS pass")
	mustLine(t, r)

	for _, cmd := range []string{"LIST 2", "UIDL 2"} {
		writeLine(t, conn, cmd)
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("%s: got %q, want single-line -ERR", cmd, resp)
		}
	}

	// No stray ".\r\n" left behind: the next command must parse normally.
	writeLine(t, conn, "STAT")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("connection desynced after contract violation: got %q", resp)
	}
}

// failingBody returns some data and then a read error, simulating a backend
// (object store) failure in a streaming Session after +OK was sent.
type failingBody struct{ sent bool }

func (f *failingBody) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		return copy(p, "partial body data"), nil
	}
	return 0, fmt.Errorf("backend read failed")
}

func (f *failingBody) Close() error { return nil }

type failingRetrSession struct{ *mockSession }

func (s *failingRetrSession) Retr(ctx context.Context, msg int) (io.ReadCloser, error) {
	return &failingBody{}, nil
}

// A body read error after +OK leaves the multiline response unterminated; the
// only safe behavior is to drop the connection — no ".\r\n" terminator and no
// -ERR may follow, since the client would parse either as message content.
func TestServer_RetrBodyReadErrorClosesConnection(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &failingRetrSession{newMockSession()}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS pass")
	mustLine(t, r)

	writeLine(t, conn, "RETR 1")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("got %q, want +OK", resp)
	}

	rest, _ := io.ReadAll(r) // read until the server closes the connection
	body := string(rest)
	if !strings.Contains(body, "partial body data") {
		t.Fatalf("flushed partial body missing: %q", body)
	}
	if strings.HasSuffix(body, ".\r\n") {
		t.Fatalf("truncated response must not be terminated: %q", body)
	}
	if strings.Contains(body, "-ERR") {
		t.Fatalf("no -ERR may follow +OK in a multiline response: %q", body)
	}
}
