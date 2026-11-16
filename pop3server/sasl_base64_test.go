package pop3server_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// plainUserPass is the SASL PLAIN response for user "user", password "pass"
// ("\x00user\x00pass"), which the mock session accepts.
const plainUserPass = "AHVzZXIAcGFzcw=="

// A SASL response that is not pure base64 must be refused, never decoded with
// the offending characters skipped or trimmed. RFC 5034 section 4: "If the
// server cannot Base64 decode a client response, it MUST reject the AUTH
// command with an -ERR reply. [...] In particular, servers and clients MUST
// reject (and not ignore) any character not explicitly allowed by the Base64
// alphabet"; section 5: base64-char = ALPHA / DIGIT / "+" / "/". Go's
// base64.StdEncoding skips CR and LF anywhere in its input, so valid
// credentials with a CR spliced in, or with whitespace around them, used to
// log the client in.
func TestServer_AuthPlainRefusesNonBase64Characters(t *testing.T) {
	tests := []struct {
		name         string
		initial      bool   // the response is the AUTH initial response
		response     string // sent as is, followed by CRLF
		wantRejected bool
	}{
		{"initial response", true, plainUserPass, false},
		{"initial response, CR inside", true, "AHVz\rZXIAcGFzcw==", true},
		{"initial response, CR before the CRLF", true, plainUserPass + "\r", true},
		{"initial response, tab before the CRLF", true, plainUserPass + "\t", true},
		{"initial response, space before the CRLF", true, plainUserPass + " ", true},
		{"initial response, space inside", true, "AHVz ZXIAcGFzcw==", true},
		{"initial response, second space before it", true, " " + plainUserPass, true},
		{"initial response, text after it", true, plainUserPass + " AHVz", true},

		{"continuation", false, plainUserPass, false},
		{"continuation, CR inside", false, "AHVz\rZXIAcGFzcw==", true},
		{"continuation, CR before the CRLF", false, plainUserPass + "\r", true},
		{"continuation, lone CR", false, "\r", true},
		{"continuation, leading space", false, " " + plainUserPass, true},
		{"continuation, trailing space", false, plainUserPass + " ", true},
		{"continuation, leading tab", false, "\t" + plainUserPass, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := serve(t, pop3server.Options{
				InsecureAuth: true,
				IdleTimeout:  5 * time.Second,
				NewSession: func(*pop3server.Conn) (pop3server.Session, error) {
					return saslSession{newMockSession()}, nil
				},
			})
			conn, r := rawDial(t, addr)
			mustLine(t, r) // greeting

			if tt.initial {
				writeRaw(t, conn, "AUTH PLAIN "+tt.response+"\r\n")
			} else {
				writeLine(t, conn, "AUTH PLAIN")
				if cont := mustLine(t, r); cont != "+ " {
					t.Fatalf("AUTH PLAIN: got %q, want the empty challenge %q", cont, "+ ")
				}
				writeRaw(t, conn, tt.response+"\r\n")
			}
			resp := mustLine(t, r)
			if !tt.wantRejected {
				if resp != "+OK Authentication successful" {
					t.Fatalf("response %q: got %q, want +OK", tt.response, resp)
				}
				return
			}
			if resp != "-ERR Invalid SASL PLAIN response" {
				t.Fatalf("response %q: got %q, want -ERR Invalid SASL PLAIN response", tt.response, resp)
			}

			// The session is still in the AUTHORIZATION state, and the same
			// credentials sent as plain base64 log in on the same connection.
			writeLine(t, conn, "STAT")
			if resp := mustLine(t, r); !strings.HasPrefix(resp, "-ERR") {
				t.Fatalf("STAT after the refusal: got %q, want -ERR (not authenticated)", resp)
			}
			writeLine(t, conn, "AUTH PLAIN "+plainUserPass)
			if resp := mustLine(t, r); resp != "+OK Authentication successful" {
				t.Fatalf("AUTH PLAIN after the refusal: got %q, want +OK", resp)
			}
		})
	}
}

func writeRaw(t *testing.T, conn net.Conn, s string) {
	t.Helper()
	if _, err := conn.Write([]byte(s)); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}
