package pop3server_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
)

// Command keywords and SASL mechanism names are case-insensitive over US-ASCII
// only: RFC 1939 section 3, "Commands in the POP3 consist of a case-insensitive
// keyword [...] Keywords and arguments consist of printable ASCII characters",
// and RFC 4422 section 3.1 names mechanisms with "ASCII [ASCII] uppercase
// letters, digits, hyphens, and/or underscores". strings.ToUpper maps U+0131
// (LATIN SMALL LETTER DOTLESS I) to "I" and U+017F (LATIN SMALL LETTER LONG S)
// to "S": a look-alike must be refused as an unknown command or mechanism,
// never executed as the keyword.
func TestServer_KeywordLookalikesAreNotKeywords(t *testing.T) {
	tests := []struct {
		name  string
		login bool // log in with USER/PASS first
		line  string
		want  string // prefix of the reply
	}{
		{"USER with long s", false, "UſER user", "-ERR"},
		{"QUIT with dotless i", false, "QUıT", "-ERR"},
		{"AUTH mechanism with dotless i", false, "AUTH PLAıN", "-ERR"},
		{"STAT with long s", true, "ſTAT", "-ERR"},
		{"LIST with dotless i", true, "LıST", "-ERR"},
		{"RSET with long s", true, "RſET", "-ERR"},

		// ASCII letters in any case are still the keywords.
		{"lower-case USER", false, "user user", "+OK"},
		{"lower-case AUTH mechanism", false, "auth plain", "+"},
		{"lower-case STAT", true, "stat", "+OK"},
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

			if tt.login {
				writeLine(t, conn, "USER user")
				mustLine(t, r)
				writeLine(t, conn, "PASS pass")
				if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
					t.Fatalf("PASS: got %q", resp)
				}
			}

			writeLine(t, conn, tt.line)
			if resp := mustLine(t, r); !strings.HasPrefix(resp, tt.want) {
				t.Fatalf("%s: got %q, want %q", tt.line, resp, tt.want)
			}
			if tt.want != "-ERR" {
				return
			}

			// The connection is still in service, in the same state.
			writeLine(t, conn, "NOOP")
			want := "-ERR" // NOOP is a TRANSACTION command
			if tt.login {
				want = "+OK"
			}
			if resp := mustLine(t, r); !strings.HasPrefix(resp, want) {
				t.Fatalf("NOOP after %s: got %q, want %q", tt.line, resp, want)
			}
		})
	}
}

// SuppressedCaps names capabilities case-insensitively over ASCII only: a
// look-alike entry suppresses nothing.
func TestServer_SuppressedCapsLookalike(t *testing.T) {
	addr := serve(t, pop3server.Options{
		InsecureAuth:   true,
		IdleTimeout:    5 * time.Second,
		SuppressedCaps: []string{"UſER"},
	})
	conn, r := rawDial(t, addr)
	mustLine(t, r) // greeting

	writeLine(t, conn, "CAPA")
	if resp := mustLine(t, r); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("CAPA: got %q", resp)
	}
	var caps []string
	for {
		line := mustLine(t, r)
		if line == "." {
			break
		}
		caps = append(caps, line)
	}
	for _, c := range caps {
		if c == "USER" {
			return
		}
	}
	t.Fatalf("USER missing from CAPA %q: suppressed by the look-alike \"UſER\"", caps)
}
