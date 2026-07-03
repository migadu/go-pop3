package pop3server_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

func serverTLSConfig(t *testing.T) *tls.Config {
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
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// A failed STLS handshake (client sends non-TLS bytes) must tear the
// connection down rather than looping in a broken half-plaintext state.
func TestServer_STLSHandshakeFailureCloses(t *testing.T) {
	addr := serve(t, pop3server.Options{
		TLSConfig:   serverTLSConfig(t),
		IdleTimeout: 5 * time.Second,
	})

	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting
	writeLine(t, conn, "STLS")
	if line := mustLine(t, r); line != "+OK Begin TLS negotiation" {
		t.Fatalf("STLS ack: %q", line)
	}

	// Send bytes that are not a valid TLS ClientHello.
	if _, err := conn.Write([]byte("this is not a tls handshake\r\n")); err != nil {
		t.Fatal(err)
	}

	// The server must close the connection promptly. Reading should hit EOF
	// (or a reset) well within the read deadline set by rawDial.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("expected connection to be closed after failed STLS handshake")
	}
}

// A client that sends STLS and then stalls (never starts the TLS handshake)
// must not hold the connection open indefinitely: the handshake is bounded by
// the (auth) idle deadline.
func TestServer_STLSHandshakeStallBounded(t *testing.T) {
	addr := serve(t, pop3server.Options{
		TLSConfig:       serverTLSConfig(t),
		IdleTimeout:     30 * time.Second,
		AuthIdleTimeout: 300 * time.Millisecond,
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	// greeting + STLS ack
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("STLS\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	// Now stall: send no ClientHello. The handshake deadline (AuthIdleTimeout)
	// must fire and close the connection. Give it generous headroom; without
	// the deadline this read would block until IdleTimeout (30s) or forever.
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = r.ReadByte()
	if err == nil {
		t.Fatal("expected connection close after stalled STLS handshake")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("handshake stall was not bounded by AuthIdleTimeout: closed after %v", elapsed)
	}
}
