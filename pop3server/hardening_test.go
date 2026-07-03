package pop3server_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// serve starts a server with the given options on a random port and returns
// its address. NewSession is filled with a default mock session when unset.
func serve(t *testing.T, opts pop3server.Options) string {
	t.Helper()
	if opts.NewSession == nil {
		opts.NewSession = func(*pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := pop3server.New(opts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// rawDial opens a raw connection with a read deadline for test safety.
func rawDial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

func mustLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func writeLine(t *testing.T, conn net.Conn, s string) {
	t.Helper()
	if _, err := conn.Write([]byte(s + "\r\n")); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}

// --- E1: MaxErrors is enforced for failed logins ---

func TestServer_MaxErrorsClosesOnFailedLogins(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    3,
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	// Three failed logins should trip MaxErrors and close the connection.
	var sawTooMany bool
	for i := 0; i < 3; i++ {
		writeLine(t, conn, "USER user")
		mustLine(t, r) // +OK
		writeLine(t, conn, "PASS wrong")
		resp := mustLine(t, r) // -ERR auth failed
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d PASS: got %q", i, resp)
		}
	}

	// After the third failure the server must send "Too many errors" and drop
	// the connection. Drain until EOF.
	for {
		line, err := r.ReadString('\n')
		if strings.Contains(line, "Too many errors") {
			sawTooMany = true
		}
		if err != nil {
			break // EOF / closed — this is the fix for E1
		}
	}
	if !sawTooMany {
		t.Fatal("expected 'Too many errors' before close")
	}
}

// --- E2: an abandoned AUTH continuation is bounded, not a slowloris ---

// saslSession adds SASL PLAIN to the mock session so AUTH reaches the
// continuation path.
type saslSession struct{ *mockSession }

func (saslSession) AuthenticateMechanisms() []string { return []string{"PLAIN"} }

func (s saslSession) AuthenticatePlain(ctx context.Context, _identity, user, pass string) error {
	return s.Login(ctx, user, pass)
}

func TestServer_AuthContinuationDeadline(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth:    true,
		AuthIdleTimeout: 700 * time.Millisecond,
		IdleTimeout:     30 * time.Second, // long; must NOT govern the continuation
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return saslSession{newMockSession()}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	// Request AUTH PLAIN with no initial response, then go silent.
	writeLine(t, conn, "AUTH PLAIN")
	if cont := mustLine(t, r); !strings.HasPrefix(cont, "+ ") && cont != "+" {
		t.Fatalf("expected continuation prompt, got %q", cont)
	}

	// The connection must be closed within ~2×AuthIdleTimeout, not IdleTimeout.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("expected connection to close after silent AUTH continuation")
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("continuation close took %v, expected ~AuthIdleTimeout", elapsed)
	}
}

// --- E5: MaxErrors negative disables the limit ---

func TestServer_MaxErrorsDisabled(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		MaxErrors:    -1, // disabled
		IdleTimeout:  5 * time.Second,
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	for i := 0; i < 8; i++ {
		writeLine(t, conn, "USER user")
		mustLine(t, r)
		writeLine(t, conn, "PASS wrong")
		if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("iter %d: got %q", i, resp)
		}
	}

	// Still alive: a valid login must succeed.
	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS pass")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("login after many failures with limit disabled: got %q", resp)
	}
}

// --- G3/G4: *Error controls response code and closes the connection ---

type errorSession struct {
	mockSession
	err error
}

func (s *errorSession) Login(ctx context.Context, user, pass string) error { return s.err }

func TestServer_ErrorTypeResponseAndClose(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &errorSession{err: &pop3server.Error{Code: "SYS/TEMP", Message: "blocked", Close: true}}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS whatever")
	if resp := mustLine(t, r); resp != "-ERR [SYS/TEMP] blocked" {
		t.Fatalf("got %q, want -ERR [SYS/TEMP] blocked", resp)
	}
	// Close is requested, so the next read should hit EOF.
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("expected connection to be closed after Error{Close:true}")
	}
}

// --- StrictSessionErrors: plain session errors must not leak on the wire ---

func TestServer_StrictSessionErrors(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth:        true,
		StrictSessionErrors: true,
		IdleTimeout:         5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &errorSession{err: errors.New("pgx: connect to db-internal-host:5432 refused")}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r)
	writeLine(t, conn, "PASS whatever")
	if resp := mustLine(t, r); resp != "-ERR internal error" {
		t.Fatalf("strict mode leaked error text: %q", resp)
	}

	// *Error responses must still pass through untouched under strict mode.
	addr2 := serve(t, pop3server.Options{
		InsecureAuth:        true,
		StrictSessionErrors: true,
		IdleTimeout:         5 * time.Second,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return &errorSession{err: &pop3server.Error{Code: "AUTH", Message: "authentication failed"}}, nil
		},
	})
	conn2, r2 := rawDial(t, addr2)
	mustLine(t, r2) // greeting
	writeLine(t, conn2, "USER user")
	mustLine(t, r2)
	writeLine(t, conn2, "PASS whatever")
	if resp := mustLine(t, r2); resp != "-ERR [AUTH] authentication failed" {
		t.Fatalf("strict mode altered *Error response: %q", resp)
	}
}

// --- G2: UnknownCommandHandler (XCLIENT-style extension) ---

func TestServer_UnknownCommandHandler(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		UnknownCommandHandler: func(_ context.Context, c *pop3server.Conn, cmd string, args []string) (bool, bool) {
			if cmd == "XCLIENT" {
				c.OK("XCLIENT " + strings.Join(args, " "))
				return true, false
			}
			return false, false
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "XCLIENT ADDR=203.0.113.9")
	if resp := mustLine(t, r); resp != "+OK XCLIENT ADDR=203.0.113.9" {
		t.Fatalf("XCLIENT: got %q", resp)
	}

	// Unhandled unknown command still errors and the connection stays open.
	writeLine(t, conn, "BOGUS")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("BOGUS: got %q", resp)
	}
	writeLine(t, conn, "QUIT")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT: got %q", resp)
	}
}

// --- Tier 3: Conn.Hijack preserves the pipelined command remainder ---

type hijackSession struct {
	mockSession
	conn *pop3server.Conn
}

func (s *hijackSession) Login(ctx context.Context, user, pass string) error {
	raw, buffered, err := s.conn.Hijack()
	if err != nil {
		return err
	}
	defer raw.Close()
	// Take over the raw connection: announce, then echo whatever the client
	// pipelined in the same segment as PASS.
	fmt.Fprintf(raw, "+RELAY ready\r\n")
	line, _ := buffered.ReadString('\n')
	fmt.Fprintf(raw, "ECHO %s\r\n", strings.TrimRight(line, "\r\n"))
	return nil
}

func TestServer_Hijack(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
			return &hijackSession{conn: c}, nil
		},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "USER user")
	mustLine(t, r) // +OK

	// Pipeline PASS and a follow-up command in a single write; the follow-up
	// must survive the hand-off (H6-style preservation).
	if _, err := conn.Write([]byte("PASS pass\r\nHELLO\r\n")); err != nil {
		t.Fatal(err)
	}

	if resp := mustLine(t, r); resp != "+RELAY ready" {
		t.Fatalf("expected +RELAY ready (not the library +OK), got %q", resp)
	}
	if resp := mustLine(t, r); resp != "ECHO HELLO" {
		t.Fatalf("expected pipelined remainder echoed, got %q", resp)
	}
	if _, err := r.ReadString('\n'); err != io.EOF && err == nil {
		t.Fatal("expected connection closed by relay")
	}
}

// --- G5: configurable greeting and reject banner ---

func TestServer_ConfigurableGreeting(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		Greeting:     "mail.example.com POP3",
	})
	_, r := rawDial(t, addr)
	if g := mustLine(t, r); g != "+OK mail.example.com POP3" {
		t.Fatalf("greeting: got %q", g)
	}
}

func TestServer_RejectBannerFromError(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth: true,
		NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
			return nil, &pop3server.Error{Code: "IN-USE", Message: "Too many connections"}
		},
	})
	_, r := rawDial(t, addr)
	// Rejection happens before the greeting; first line is the banner.
	if line := mustLine(t, r); line != "-ERR [IN-USE] Too many connections" {
		t.Fatalf("reject banner: got %q", line)
	}
}
