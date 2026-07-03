package pop3server_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// mockSession is a minimal session implementation for integration tests.
type mockSession struct {
	messages []mockMessage
	deleted  map[int]bool
}

type mockMessage struct {
	num  int
	size int64
	uid  string
	body string
}

func newMockSession() *mockSession {
	return &mockSession{
		messages: []mockMessage{
			{num: 1, size: 100, uid: "uid1", body: "Subject: test1\r\n\r\nBody of message 1\r\n"},
			{num: 2, size: 200, uid: "uid2", body: "Subject: test2\r\n\r\nBody of message 2\r\n"},
			{num: 3, size: 150, uid: "uid3", body: "Subject: test3\r\n\r\n.Dot at start\r\n"},
		},
		deleted: make(map[int]bool),
	}
}

func (s *mockSession) Close() error { return nil }

func (s *mockSession) Login(ctx context.Context, username, password string) error {
	if username == "user" && password == "pass" {
		return nil
	}
	return fmt.Errorf("[AUTH] Authentication failed")
}

func (s *mockSession) Stat(ctx context.Context) (int, int64, error) {
	count := 0
	var size int64
	for i := range s.messages {
		if !s.deleted[i+1] {
			count++
			size += s.messages[i].size
		}
	}
	return count, size, nil
}

func (s *mockSession) List(ctx context.Context, msg int) ([]pop3.MessageInfo, error) {
	if msg > 0 {
		if msg > len(s.messages) || s.deleted[msg] {
			return nil, fmt.Errorf("no such message")
		}
		return []pop3.MessageInfo{{Num: msg, Size: s.messages[msg-1].size}}, nil
	}
	var items []pop3.MessageInfo
	for i, m := range s.messages {
		if !s.deleted[i+1] {
			items = append(items, pop3.MessageInfo{Num: i + 1, Size: m.size})
		}
	}
	return items, nil
}

func (s *mockSession) Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error) {
	if msg > 0 {
		if msg > len(s.messages) || s.deleted[msg] {
			return nil, fmt.Errorf("no such message")
		}
		return []pop3.MessageUidl{{Num: msg, UniqueID: s.messages[msg-1].uid}}, nil
	}
	var items []pop3.MessageUidl
	for i, m := range s.messages {
		if !s.deleted[i+1] {
			items = append(items, pop3.MessageUidl{Num: i + 1, UniqueID: m.uid})
		}
	}
	return items, nil
}

func (s *mockSession) Retr(ctx context.Context, msg int) (io.ReadCloser, error) {
	if msg < 1 || msg > len(s.messages) || s.deleted[msg] {
		return nil, fmt.Errorf("no such message")
	}
	return io.NopCloser(strings.NewReader(s.messages[msg-1].body)), nil
}

func (s *mockSession) Top(ctx context.Context, msg int, lines int) (io.ReadCloser, error) {
	return s.Retr(ctx, msg) // simplified: returns full body
}

func (s *mockSession) Dele(ctx context.Context, msg int) error {
	if msg < 1 || msg > len(s.messages) {
		return fmt.Errorf("no such message")
	}
	if s.deleted[msg] {
		return fmt.Errorf("message already deleted")
	}
	s.deleted[msg] = true
	return nil
}

func (s *mockSession) Rset(ctx context.Context) error {
	s.deleted = make(map[int]bool)
	return nil
}

func (s *mockSession) Noop(ctx context.Context) error {
	return nil
}

func (s *mockSession) Quit(ctx context.Context) (int, error) {
	return len(s.deleted), nil
}

// startTestServer starts a POP3 server on a random port and returns the
// address. The caller should call the returned cleanup function.
func startTestServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth: true, // allow auth without TLS for testing
		IdleTimeout:  5 * time.Second,
	})

	go srv.Serve(ln)

	return ln.Addr().String(), func() {
		srv.Close()
	}
}

func dial(t *testing.T, addr string) *bufio.ReadWriter {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// Read greeting
	greeting, err := rw.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("expected +OK greeting, got %q", greeting)
	}

	return rw
}

func sendCmd(t *testing.T, rw *bufio.ReadWriter, cmd string) string {
	t.Helper()
	rw.WriteString(cmd)
	rw.WriteString("\r\n")
	rw.Flush()
	resp, err := rw.ReadString('\n')
	if err != nil {
		t.Fatalf("reading response to %q: %v", cmd, err)
	}
	return strings.TrimRight(resp, "\r\n")
}

func readMultiLine(t *testing.T, rw *bufio.ReadWriter) []string {
	t.Helper()
	var lines []string
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		lines = append(lines, line)
	}
	return lines
}

// --- Integration tests ---

func TestServer_LoginAndStat(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)

	resp := sendCmd(t, rw, "USER user")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER: %s", resp)
	}

	resp = sendCmd(t, rw, "PASS pass")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}

	resp = sendCmd(t, rw, "STAT")
	if !strings.HasPrefix(resp, "+OK 3 450") {
		t.Fatalf("STAT: got %q, want +OK 3 450", resp)
	}
}

func TestServer_LoginFailure(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)

	sendCmd(t, rw, "USER user")
	resp := sendCmd(t, rw, "PASS wrong")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("expected -ERR, got %q", resp)
	}
}

func TestServer_ListAndUidl(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)
	sendCmd(t, rw, "USER user")
	sendCmd(t, rw, "PASS pass")

	// LIST all
	resp := sendCmd(t, rw, "LIST")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("LIST: %s", resp)
	}
	lines := readMultiLine(t, rw)
	if len(lines) != 3 {
		t.Fatalf("LIST: got %d lines, want 3", len(lines))
	}

	// LIST single
	resp = sendCmd(t, rw, "LIST 2")
	if !strings.Contains(resp, "2 200") {
		t.Fatalf("LIST 2: got %q", resp)
	}

	// UIDL all
	resp = sendCmd(t, rw, "UIDL")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("UIDL: %s", resp)
	}
	lines = readMultiLine(t, rw)
	if len(lines) != 3 {
		t.Fatalf("UIDL: got %d lines, want 3", len(lines))
	}
}

func TestServer_RetrWithDotStuffing(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)
	sendCmd(t, rw, "USER user")
	sendCmd(t, rw, "PASS pass")

	// RETR message 3 (has a line starting with '.')
	resp := sendCmd(t, rw, "RETR 3")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("RETR 3: %s", resp)
	}
	lines := readMultiLine(t, rw)

	// The line ".Dot at start" should be dot-stuffed to "..Dot at start"
	found := false
	for _, line := range lines {
		if strings.Contains(line, "..Dot at start") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dot-stuffed line '..Dot at start' in RETR output, got %v", lines)
	}
}

func TestServer_DeleRsetQuit(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)
	sendCmd(t, rw, "USER user")
	sendCmd(t, rw, "PASS pass")

	// DELE 1
	resp := sendCmd(t, rw, "DELE 1")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("DELE: %s", resp)
	}

	// STAT should show 2 messages now
	resp = sendCmd(t, rw, "STAT")
	if !strings.HasPrefix(resp, "+OK 2") {
		t.Fatalf("STAT after DELE: got %q", resp)
	}

	// RSET undoes the delete
	resp = sendCmd(t, rw, "RSET")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("RSET: %s", resp)
	}

	resp = sendCmd(t, rw, "STAT")
	if !strings.HasPrefix(resp, "+OK 3") {
		t.Fatalf("STAT after RSET: got %q", resp)
	}

	// QUIT
	resp = sendCmd(t, rw, "QUIT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT: %s", resp)
	}
}

func TestServer_Capa(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)

	resp := sendCmd(t, rw, "CAPA")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA: %s", resp)
	}
	lines := readMultiLine(t, rw)

	// Check for required capabilities
	caps := make(map[string]bool)
	for _, line := range lines {
		caps[strings.Fields(line)[0]] = true
	}

	for _, required := range []string{"TOP", "UIDL", "USER", "RESP-CODES", "PIPELINING"} {
		if !caps[required] {
			t.Errorf("CAPA missing %s, got: %v", required, lines)
		}
	}
}

func TestServer_QuitBeforeAuth(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)

	resp := sendCmd(t, rw, "QUIT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT before auth: %s", resp)
	}
}

func TestServer_AuthIdleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth:    true,
		AuthIdleTimeout: 1 * time.Second,  // 1s pre-auth
		IdleTimeout:     10 * time.Second, // 10s post-auth (should not trigger)
	})
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("expected +OK, got %q", greeting)
	}

	// Wait for auth idle timeout to fire (1s + buffer)
	time.Sleep(2 * time.Second)

	// Should receive -ERR timeout
	errMsg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected timeout error message, got err: %v", err)
	}
	if !strings.HasPrefix(errMsg, "-ERR") || !strings.Contains(errMsg, "timed out") {
		t.Fatalf("expected -ERR timeout, got %q", errMsg)
	}
}

func TestServer_AbsoluteSessionTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth:           true,
		IdleTimeout:            10 * time.Second,
		AbsoluteSessionTimeout: 2 * time.Second, // 2s total
	})
	go srv.Serve(ln)
	defer srv.Close()

	rw := dial(t, ln.Addr().String())

	// Authenticate
	sendCmd(t, rw, "USER user")
	resp := sendCmd(t, rw, "PASS pass")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}

	// Keep sending NOOP to stay active but hit absolute timeout
	time.Sleep(3 * time.Second)

	// Next command should fail or we should get -ERR
	rw.WriteString("NOOP\r\n")
	rw.Flush()
	line, err := rw.ReadString('\n')
	if err != nil {
		// Connection closed — expected
		return
	}
	if strings.HasPrefix(line, "-ERR") && strings.Contains(line, "IN-USE") {
		// Got the expected error
		return
	}
	t.Fatalf("expected -ERR [IN-USE] or connection close, got %q", line)
}

func TestServer_BenignErrorsDoNotDisconnect(t *testing.T) {
	// Verify that session method errors (e.g., "no such message") do NOT
	// count toward MaxErrors and do NOT disconnect the client.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		MaxErrors:    3, // Very low threshold
	})
	go srv.Serve(ln)
	defer srv.Close()

	rw := dial(t, ln.Addr().String())

	// Authenticate
	sendCmd(t, rw, "USER user")
	sendCmd(t, rw, "PASS pass")

	// Send 10 requests for non-existent messages — these should NOT
	// count as errors and should NOT trigger disconnect.
	for i := 0; i < 10; i++ {
		resp := sendCmd(t, rw, "RETR 999")
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("RETR 999 iteration %d: expected -ERR, got %q", i, resp)
		}
	}

	// Connection should still be alive — verify with STAT
	resp := sendCmd(t, rw, "STAT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT after 10 benign errors: expected +OK, got %q", resp)
	}
}

func TestServer_LAST_Rejected(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	rw := dial(t, addr)

	resp := sendCmd(t, rw, "LAST")
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("LAST: expected -ERR, got %q", resp)
	}
	if !strings.Contains(resp, "obsolete") {
		t.Fatalf("LAST: expected 'obsolete' in response, got %q", resp)
	}

	// Connection should still be alive (LAST doesn't count as error)
	resp = sendCmd(t, rw, "QUIT")
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT after LAST: expected +OK, got %q", resp)
	}
}
