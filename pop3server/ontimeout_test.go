package pop3server_test

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// timeoutKindRecorder collects OnTimeout invocations for assertions.
type timeoutKindRecorder struct {
	mu    sync.Mutex
	kinds []string
}

func (r *timeoutKindRecorder) record(kind string) {
	r.mu.Lock()
	r.kinds = append(r.kinds, kind)
	r.mu.Unlock()
}

func (r *timeoutKindRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.kinds...)
}

func TestServer_OnTimeoutHookIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	rec := &timeoutKindRecorder{}
	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth: true,
		IdleTimeout:  1 * time.Second,
		OnTimeout:    rec.record,
	})
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("greeting: %q err=%v", greeting, err)
	}

	// Wait for the idle timeout to fire (1s + buffer).
	time.Sleep(2 * time.Second)

	errMsg, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected timeout error message, got err: %v", err)
	}
	if !strings.HasPrefix(errMsg, "-ERR") {
		t.Fatalf("expected -ERR timeout, got %q", errMsg)
	}

	// The hook must fire exactly once, with the idle kind — embedders count
	// disconnects from it, so a double invocation would skew their metrics.
	if kinds := rec.snapshot(); len(kinds) != 1 || kinds[0] != pop3server.TimeoutIdle {
		t.Fatalf("expected exactly one OnTimeout(%q), got %v", pop3server.TimeoutIdle, kinds)
	}
}

func TestServer_OnTimeoutHookAbsolute(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	rec := &timeoutKindRecorder{}
	srv := pop3server.New(pop3server.Options{
		NewSession: func(conn *pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		},
		InsecureAuth:           true,
		IdleTimeout:            10 * time.Second,
		AbsoluteSessionTimeout: 1 * time.Second,
		OnTimeout:              rec.record,
	})
	go srv.Serve(ln)
	defer srv.Close()

	rw := dial(t, ln.Addr().String())

	sendCmd(t, rw, "USER user")
	if resp := sendCmd(t, rw, "PASS pass"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS: %s", resp)
	}

	// Sit past the absolute limit; the capped read deadline fires and the
	// server must classify it as an absolute (not idle) timeout.
	time.Sleep(2 * time.Second)

	line, err := rw.ReadString('\n')
	if err == nil && (!strings.HasPrefix(line, "-ERR") || !strings.Contains(line, "IN-USE")) {
		t.Fatalf("expected -ERR [IN-USE] or connection close, got %q", line)
	}

	if kinds := rec.snapshot(); len(kinds) != 1 || kinds[0] != pop3server.TimeoutAbsolute {
		t.Fatalf("expected exactly one OnTimeout(%q), got %v", pop3server.TimeoutAbsolute, kinds)
	}
}
