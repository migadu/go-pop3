package pop3server_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// drainForTooMany reads until the connection closes, reporting whether the
// "Too many errors" notice was seen before EOF.
func drainForTooMany(r interface{ ReadString(byte) (string, error) }) bool {
	saw := false
	for {
		line, err := r.ReadString('\n')
		if strings.Contains(line, "Too many errors") {
			saw = true
		}
		if err != nil {
			return saw
		}
	}
}

// A library-detected invalid argument (a non-numeric message number) is a
// client protocol error and must count toward MaxErrors — in contrast to a
// session "no such message" error (RETR 999), which does not
// (TestServer_BenignErrorsDoNotDisconnect).
func TestServer_InvalidArgCountsTowardMaxErrors(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    3,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS pass")
	mustLine(t, r) // +OK auth

	// Three malformed RETRs (non-numeric message number) must trip the limit.
	for i := 0; i < 3; i++ {
		writeLine(t, conn, "RETR notanumber")
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d: got %q", i, resp)
		}
	}
	if !drainForTooMany(r) {
		t.Fatal("expected 'Too many errors' + close after 3 invalid-argument errors")
	}
}

// A malformed / out-of-order pre-auth command (PASS before USER) is a client
// protocol error and must count toward MaxErrors.
func TestServer_OutOfOrderCommandCountsTowardMaxErrors(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    3,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	for i := 0; i < 3; i++ {
		writeLine(t, conn, "PASS secret") // no USER first
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d: got %q", i, resp)
		}
	}
	if !drainForTooMany(r) {
		t.Fatal("expected 'Too many errors' + close after 3 out-of-order commands")
	}
}

// LAST remains a deliberate exemption: legacy clients probe for it and it must
// not count toward MaxErrors even after the stricter accounting.
func TestServer_LASTStillExemptFromMaxErrors(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    3,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	// Five LASTs (> MaxErrors) must not disconnect.
	for i := 0; i < 5; i++ {
		writeLine(t, conn, "LAST")
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d: got %q", i, resp)
		}
	}
	// Connection still usable.
	writeLine(t, conn, "USER user")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("connection dropped after repeated LAST: got %q", resp)
	}
}
