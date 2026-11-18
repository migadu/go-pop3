package pop3server_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// mockSessionUTF8 extends mockSession with the UTF8 extension so the tests
// can drive the RFC 6856 paths.
type mockSessionUTF8 struct {
	*mockSession
	utf8Enabled bool
}

func (s *mockSessionUTF8) EnableUTF8(ctx context.Context) error {
	s.utf8Enabled = true
	return nil
}

// startServerWithOpts starts a POP3 server with caller-controlled options,
// filling in only the listener plumbing.
func startServerWithOpts(t *testing.T, opts pop3server.Options) (addr string, cleanup func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 5 * time.Second
	}
	srv := pop3server.New(opts)
	go srv.Serve(ln)

	return ln.Addr().String(), func() { srv.Close() }
}

// TestServer_UTF8PostAuth_OutlookCompat is the regression test for the
// production incident where classic Outlook, having seen UTF8 in the pre-auth
// CAPA, sent "UTF8" immediately after PASS, received -ERR, and aborted the
// whole download (0x800CCC90). RFC 6856 §2 nominally restricts the command to
// the AUTHORIZATION state, but interop demands the post-auth form succeed.
func TestServer_UTF8PostAuth_OutlookCompat(t *testing.T) {
	session := &mockSessionUTF8{mockSession: newMockSession()}
	addr, cleanup := startServerWithOpts(t, pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return session, nil
		},
		InsecureAuth: true,
	})
	defer cleanup()

	rw := dial(t, addr)

	// Outlook's exact sequence: CAPA, USER, PASS, UTF8.
	resp := sendCmd(t, rw, "CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA: %s", resp)
	}
	caps := readMultiLine(t, rw)
	found := false
	for _, c := range caps {
		if strings.EqualFold(c, "UTF8") {
			found = true
		}
	}
	if !found {
		t.Fatalf("UTF8 not advertised in CAPA: %v", caps)
	}

	if resp := sendCmd(t, rw, "USER user"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER: %s", resp)
	}
	if resp := sendCmd(t, rw, "PASS pass"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}

	resp = sendCmd(t, rw, "UTF8")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("post-auth UTF8 must be accepted (Outlook aborts on -ERR), got: %s", resp)
	}
	if !session.utf8Enabled {
		t.Fatal("EnableUTF8 was not called for post-auth UTF8")
	}

	// The session must remain usable afterwards.
	if resp := sendCmd(t, rw, "STAT"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT after UTF8: %s", resp)
	}
}

// TestServer_UTF8PreAuth verifies the RFC 6856 §2 position: UTF8 before
// authentication is accepted and UTF-8 mode is enabled for the session.
func TestServer_UTF8PreAuth(t *testing.T) {
	session := &mockSessionUTF8{mockSession: newMockSession()}
	addr, cleanup := startServerWithOpts(t, pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return session, nil
		},
		InsecureAuth: true,
	})
	defer cleanup()

	rw := dial(t, addr)

	if resp := sendCmd(t, rw, "UTF8"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("pre-auth UTF8: %s", resp)
	}
	if !session.utf8Enabled {
		t.Fatal("EnableUTF8 was not called for pre-auth UTF8")
	}

	if resp := sendCmd(t, rw, "USER user"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER: %s", resp)
	}
	if resp := sendCmd(t, rw, "PASS pass"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}
}

// TestServer_UTF8NotSupported verifies that a session without SessionUTF8
// gets -ERR in both states (such a server never advertises UTF8, so no
// CAPA-driven client will send it).
func TestServer_UTF8NotSupported(t *testing.T) {
	addr, cleanup := startServerWithOpts(t, pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth: true,
	})
	defer cleanup()

	rw := dial(t, addr)

	if resp := sendCmd(t, rw, "UTF8"); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("pre-auth UTF8 without SessionUTF8: %s", resp)
	}
	if resp := sendCmd(t, rw, "USER user"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER: %s", resp)
	}
	if resp := sendCmd(t, rw, "PASS pass"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}
	if resp := sendCmd(t, rw, "UTF8"); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("post-auth UTF8 without SessionUTF8: %s", resp)
	}
}

// TestServer_SuppressedCaps verifies that SuppressedCaps hides capabilities
// from CAPA without disabling the commands: a proxy fronting backends that
// cannot honor UTF8/LANG hides them (so CAPA-driven clients like Outlook
// never send them) while still answering a blind pre-auth UTF8.
func TestServer_SuppressedCaps(t *testing.T) {
	session := &mockSessionUTF8{mockSession: newMockSession()}
	addr, cleanup := startServerWithOpts(t, pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return session, nil
		},
		InsecureAuth:   true,
		SuppressedCaps: []string{"utf8", "LANG"}, // case-insensitive
	})
	defer cleanup()

	rw := dial(t, addr)

	resp := sendCmd(t, rw, "CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA: %s", resp)
	}
	caps := readMultiLine(t, rw)
	for _, c := range caps {
		name := strings.Fields(c)[0]
		if strings.EqualFold(name, "UTF8") || strings.EqualFold(name, "LANG") {
			t.Fatalf("suppressed capability %q still advertised: %v", name, caps)
		}
	}
	// Baseline caps must be unaffected.
	for _, want := range []string{"TOP", "UIDL", "PIPELINING"} {
		found := false
		for _, c := range caps {
			if strings.EqualFold(strings.Fields(c)[0], want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("capability %q missing from CAPA: %v", want, caps)
		}
	}

	// The command still works even though it is not advertised.
	if resp := sendCmd(t, rw, "UTF8"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("UTF8 with suppressed advertisement: %s", resp)
	}
	if !session.utf8Enabled {
		t.Fatal("EnableUTF8 was not called")
	}
}

// utf8CapLines returns the CAPA lines whose tag is UTF8 (case-insensitive).
func utf8CapLines(t *testing.T, opts pop3server.Options, session pop3server.Session) []string {
	t.Helper()
	opts.NewSession = func(conn *pop3server.Conn) (pop3server.Session, error) {
		return session, nil
	}
	opts.InsecureAuth = true
	addr, cleanup := startServerWithOpts(t, opts)
	t.Cleanup(cleanup)

	rw := dial(t, addr)
	if resp := sendCmd(t, rw, "CAPA"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA: %s", resp)
	}
	var lines []string
	for _, c := range readMultiLine(t, rw) {
		if f := strings.Fields(c); len(f) > 0 && strings.EqualFold(f[0], "UTF8") {
			lines = append(lines, c)
		}
	}
	return lines
}

// TestServer_UTF8UserCapability covers the USER argument of the UTF8
// capability. RFC 6856 §2.2: "If the USER argument is included with this
// capability, it indicates that the server accepts UTF-8 usernames and
// passwords. [...] Clients MUST NOT use UTF-8 characters when authenticating
// if the server did not include the USER argument in the UTF8 capability
// response." A server that accepts UTF-8 credentials sets Options.UTF8User;
// the default stays a bare UTF8, and SuppressedCaps still hides the line.
func TestServer_UTF8UserCapability(t *testing.T) {
	cases := []struct {
		name    string
		opts    pop3server.Options
		session func() pop3server.Session
		want    []string
	}{
		{
			name:    "default is a bare UTF8",
			session: func() pop3server.Session { return &mockSessionUTF8{mockSession: newMockSession()} },
			want:    []string{"UTF8"},
		},
		{
			name:    "UTF8User adds the USER argument",
			opts:    pop3server.Options{UTF8User: true},
			session: func() pop3server.Session { return &mockSessionUTF8{mockSession: newMockSession()} },
			want:    []string{"UTF8 USER"},
		},
		{
			name:    "SuppressedCaps hides UTF8 USER",
			opts:    pop3server.Options{UTF8User: true, SuppressedCaps: []string{"utf8"}},
			session: func() pop3server.Session { return &mockSessionUTF8{mockSession: newMockSession()} },
			want:    nil,
		},
		{
			name:    "UTF8User without SessionUTF8 advertises nothing",
			opts:    pop3server.Options{UTF8User: true},
			session: func() pop3server.Session { return newMockSession() },
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := utf8CapLines(t, tc.opts, tc.session())
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("CAPA UTF8 lines = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestServer_UTF8UserOnlyWhenUserOffered: the USER argument says the USER and
// PASS commands accept UTF-8 (RFC 6856 §2.2), so it is advertised only when
// login is: on a plaintext connection without InsecureAuth, CAPA lists neither
// USER nor SASL, and UTF8 goes out bare. After STLS it carries the argument.
func TestServer_UTF8UserOnlyWhenUserOffered(t *testing.T) {
	session := &mockSessionUTF8{mockSession: newMockSession()}
	addr, cleanup := startServerWithOpts(t, pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return session, nil
		},
		TLSConfig: serverTLSConfig(t),
		UTF8User:  true,
	})
	defer cleanup()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	utf8Lines := func(rw *bufio.ReadWriter) []string {
		t.Helper()
		if resp := sendCmd(t, rw, "CAPA"); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("CAPA: %s", resp)
		}
		var lines []string
		for _, c := range readMultiLine(t, rw) {
			if f := strings.Fields(c); len(f) > 0 && strings.EqualFold(f[0], "UTF8") {
				lines = append(lines, c)
			}
		}
		return lines
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	if greeting, err := rw.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("greeting = %q, %v", greeting, err)
	}
	if got := utf8Lines(rw); strings.Join(got, "|") != "UTF8" {
		t.Errorf("CAPA UTF8 lines before STLS = %q, want [\"UTF8\"]", got)
	}

	if resp := sendCmd(t, rw, "STLS"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STLS: %s", resp)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
	if got := utf8Lines(rw); strings.Join(got, "|") != "UTF8 USER" {
		t.Errorf("CAPA UTF8 lines after STLS = %q, want [\"UTF8 USER\"]", got)
	}
}
