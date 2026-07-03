package pop3client_test

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3client"
)

// silentServer accepts one connection, sends a greeting, then reads commands
// without ever responding — simulating a wedged upstream backend.
func silentServer(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("+OK silent\r\n"))
		// Swallow input forever (until the connection is torn down).
		r := bufio.NewReader(conn)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// A deadline-free but cancellable context must still unblock an in-flight
// read: the cancellation guard poisons the connection deadline.
func TestClient_ContextCancelUnblocks(t *testing.T) {
	addr := silentServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := pop3client.Dial(ctx, addr, pop3client.Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if _, err := client.Cmd(ctx, "NOOP"); err == nil {
		t.Fatal("expected error after context cancellation")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Cmd blocked %v after cancellation; guard did not unblock the read", elapsed)
	}
}
