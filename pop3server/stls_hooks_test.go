package pop3server_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

type stlsHookConn struct {
	net.Conn
	reads       atomic.Uint64
	beforeWrite func([]byte)
}

func (c *stlsHookConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.reads.Add(1)
	}
	return n, err
}

func (c *stlsHookConn) Write(b []byte) (int, error) {
	if c.beforeWrite != nil {
		c.beforeWrite(b)
	}
	return c.Conn.Write(b)
}

func serveSTLSHookPipe(t *testing.T, opts pop3server.Options, wrap func(net.Conn) net.Conn) (net.Conn, *bufio.Reader) {
	t.Helper()
	plain, client := net.Pipe()
	if wrap != nil {
		plain = wrap(plain)
	}
	if opts.NewSession == nil {
		opts.NewSession = func(*pop3server.Conn) (pop3server.Session, error) {
			return newMockSession(), nil
		}
	}
	srv := pop3server.New(opts)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ServeConn(plain)
	}()
	t.Cleanup(func() {
		client.Close()
		srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("connection handler did not stop")
		}
	})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	return client, bufio.NewReader(client)
}

// Hold the TLS 1.3 client's Finished and first application record, then send
// both in one write. The server can dispatch that command without another
// underlying read after its handshake completes.
type stlsHeldWrites struct {
	net.Conn
	mu     sync.Mutex
	writes int
	held   []byte
}

func (c *stlsHeldWrites) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 1 {
		return c.Conn.Write(b)
	}
	c.held = append(c.held, b...)
	return len(b), nil
}

func (c *stlsHeldWrites) release() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.Conn.Write(c.held)
	c.held = nil
	return err
}

type stlsHookSession struct {
	*mockSession
	onLogin func()
}

func (s *stlsHookSession) Login(ctx context.Context, user, password string) error {
	s.onLogin()
	return s.mockSession.Login(ctx, user, password)
}

func TestServer_STLSHooksOrderAndCoalescedAuthentication(t *testing.T) {
	var protocolConn *pop3server.Conn
	var plainConn *stlsHookConn
	var started, completed atomic.Bool
	var handshakeReads uint64 // only accessed by the connection goroutine
	events := make(chan string, 4)
	client, r := serveSTLSHookPipe(t, pop3server.Options{
		TLSConfig: serverTLSConfig(t),
		NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
			protocolConn = c
			return &stlsHookSession{mockSession: newMockSession(), onLogin: func() {
				if !completed.Load() {
					t.Error("authentication dispatched before the completion hook returned")
				}
				if got := plainConn.reads.Load(); got != handshakeReads {
					t.Errorf("authentication needed an underlying read after the hook: reads %d -> %d", handshakeReads, got)
				}
				events <- "login"
			}}, nil
		},
		OnStartTLS: func(plain net.Conn) {
			if plain != plainConn || protocolConn.NetConn() != plain || protocolConn.IsTLS() {
				t.Error("start hook did not receive the live plaintext connection")
			}
			events <- "start"
			started.Store(true)
		},
		OnTLSHandshakeComplete: func(plain net.Conn, secure *tls.Conn) {
			if plain != plainConn || secure.NetConn() != plain {
				t.Error("completion hook transports do not match the upgrade")
			}
			if protocolConn.NetConn() != secure || !protocolConn.IsTLS() || !secure.ConnectionState().HandshakeComplete {
				t.Error("completion hook ran before the connection's TLS state was updated")
			}
			handshakeReads = plainConn.reads.Load()
			events <- "complete"
			completed.Store(true)
		},
	}, func(conn net.Conn) net.Conn {
		plainConn = &stlsHookConn{Conn: conn, beforeWrite: func(b []byte) {
			if strings.Contains(string(b), "+OK Begin TLS negotiation\r\n") {
				if !started.Load() || completed.Load() {
					t.Error("STLS response was written outside the two hook boundaries")
				}
				events <- "ack"
			}
		}}
		return plainConn
	})
	mustLine(t, r) // greeting
	writeLine(t, client, "STLS")
	if got := mustLine(t, r); got != "+OK Begin TLS negotiation" {
		t.Fatalf("STLS response = %q", got)
	}
	held := &stlsHeldWrites{Conn: client}
	secure := tls.Client(held, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(secure, "USER user\r\nPASS pass\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := held.release(); err != nil {
		t.Fatal(err)
	}
	tr := bufio.NewReader(secure)
	if got := mustLine(t, tr); got != "+OK" {
		t.Fatalf("USER response = %q", got)
	}
	if got := mustLine(t, tr); got != "+OK Authentication successful" {
		t.Fatalf("PASS response = %q", got)
	}
	for _, want := range []string{"start", "ack", "complete", "login"} {
		if got := <-events; got != want {
			t.Fatalf("hook/dispatch order: got %q, want %q", got, want)
		}
	}
}

func TestServer_STLSHooksOmittedOnRejection(t *testing.T) {
	for _, test := range []struct {
		name     string
		tls      bool
		already  bool
		auth     bool
		pipeline bool
	}{
		{name: "TLS unavailable"},
		{name: "already TLS", tls: true, already: true},
		{name: "authenticated", tls: true, auth: true},
		{name: "pipelined plaintext", tls: true, pipeline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var starts, completes atomic.Int32
			opts := pop3server.Options{
				InsecureAuth: true,
				NewSession: func(c *pop3server.Conn) (pop3server.Session, error) {
					c.SetTLS(test.already)
					return newMockSession(), nil
				},
				OnStartTLS:             func(net.Conn) { starts.Add(1) },
				OnTLSHandshakeComplete: func(net.Conn, *tls.Conn) { completes.Add(1) },
			}
			if test.tls {
				opts.TLSConfig = serverTLSConfig(t)
			}
			client, r := serveSTLSHookPipe(t, opts, nil)
			mustLine(t, r)
			if test.auth {
				for _, command := range []string{"USER user", "PASS pass"} {
					writeLine(t, client, command)
					if got := mustLine(t, r); !strings.HasPrefix(got, "+OK") {
						t.Fatalf("%s response = %q", command, got)
					}
				}
			}
			command := "STLS\r\n"
			if test.pipeline {
				command += "CAPA\r\n"
			}
			if _, err := io.WriteString(client, command); err != nil {
				t.Fatal(err)
			}
			if got := mustLine(t, r); !strings.HasPrefix(got, "-ERR") {
				t.Fatalf("STLS rejection = %q", got)
			}
			if starts.Load() != 0 || completes.Load() != 0 {
				t.Fatalf("rejected STLS ran hooks: starts=%d completes=%d", starts.Load(), completes.Load())
			}
		})
	}
}

func TestServer_STLSCompletionHookOmittedOnHandshakeFailure(t *testing.T) {
	var starts, completes atomic.Int32
	client, r := serveSTLSHookPipe(t, pop3server.Options{
		TLSConfig:              serverTLSConfig(t),
		OnStartTLS:             func(net.Conn) { starts.Add(1) },
		OnTLSHandshakeComplete: func(net.Conn, *tls.Conn) { completes.Add(1) },
	}, nil)
	mustLine(t, r)
	writeLine(t, client, "STLS")
	if got := mustLine(t, r); got != "+OK Begin TLS negotiation" {
		t.Fatalf("STLS response = %q", got)
	}
	if _, err := io.WriteString(client, "not a TLS handshake\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("reading closed connection: %v", err)
	}
	if starts.Load() != 1 || completes.Load() != 0 {
		t.Fatalf("failed handshake ran hooks: starts=%d completes=%d", starts.Load(), completes.Load())
	}
}

func TestServer_STLSHooksOmittedForImplicitTLS(t *testing.T) {
	var starts, completes atomic.Int32
	config := serverTLSConfig(t)
	client, _ := serveSTLSHookPipe(t, pop3server.Options{
		TLSConfig:              config,
		OnStartTLS:             func(net.Conn) { starts.Add(1) },
		OnTLSHandshakeComplete: func(net.Conn, *tls.Conn) { completes.Add(1) },
	}, func(conn net.Conn) net.Conn { return tls.Server(conn, config) })
	secure := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	r := bufio.NewReader(secure)
	if got := mustLine(t, r); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("TLS greeting = %q", got)
	}
	writeLine(t, secure, "QUIT")
	if got := mustLine(t, r); !strings.HasPrefix(got, "+OK") {
		t.Fatalf("QUIT response = %q", got)
	}
	if starts.Load() != 0 || completes.Load() != 0 {
		t.Fatalf("implicit TLS ran STLS hooks: starts=%d completes=%d", starts.Load(), completes.Load())
	}
}
