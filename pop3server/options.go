package pop3server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	"github.com/migadu/go-pop3/pop3"
)

// defaultMaxErrorDelay caps the progressive per-error back-off when
// Options.MaxErrorDelay is left at its zero value. It prevents a client that
// keeps erroring from being made to sleep for an unbounded amount of time
// (which would also tie up a goroutine).
const defaultMaxErrorDelay = 30 * time.Second

// defaultWriteTimeout is applied when Options.WriteTimeout is left at its
// zero value. Each buffered write (a flush chunk, typically 4096 bytes) must
// complete within this window, so even a very slow client link is fine while
// a stalled (non-reading) client cannot wedge a streamed RETR/TOP forever.
const defaultWriteTimeout = 60 * time.Second

// Options configures a POP3 server.
type Options struct {
	// NewSession is called for each new connection. The Conn provides
	// access to the underlying net.Conn (for peer address, TLS state,
	// etc.). Returning an error rejects the connection immediately: the
	// server sends "-ERR <message>" and closes the connection. The message
	// is Options.RejectMessage by default, or the wire message of a
	// *pop3server.Error if the returned error is (or wraps) one — so a
	// connection limiter can reply "-ERR [IN-USE] Too many connections".
	NewSession func(conn *Conn) (Session, error)

	// TLSConfig enables TLS support. If non-nil:
	//   - For implicit TLS listeners: connections are TLS from the start.
	//   - For plaintext listeners: the STLS capability is advertised and
	//     the library handles the TLS upgrade when the client sends STLS.
	// If nil, TLS is not available and STLS is not advertised.
	TLSConfig *tls.Config

	// Caps lists additional capabilities to advertise in the CAPA
	// response. The library automatically adds:
	//   - USER          (always, when auth is allowed)
	//   - PIPELINING    (always)
	//   - RESP-CODES    (always)
	//   - UIDL          (always)
	//   - TOP           (always)
	//   - STLS          (when TLSConfig is set and connection is plaintext)
	//   - SASL <mechs>  (when session implements SessionSASL)
	//   - LANG          (when session implements SessionLang)
	//   - UTF8          (when session implements SessionUTF8)
	//
	// Use this for implementation-specific capabilities (e.g., EXPIRE,
	// AUTH-RESP-CODE, IMPLEMENTATION).
	Caps []pop3.Capability

	// IdleTimeout is the maximum time the server waits for a command
	// from the client before disconnecting. RFC 1939 §3 mandates at
	// least 10 minutes ("auto-logout timer"). Default: 10 minutes.
	IdleTimeout time.Duration

	// AuthIdleTimeout, if non-zero, overrides IdleTimeout during the
	// AUTHORIZATION state (before authentication succeeds). This allows
	// a shorter timeout for unauthenticated connections (e.g. 30s) while
	// keeping a generous idle timeout for authenticated sessions. It also
	// bounds the read of a SASL continuation line (AUTH PLAIN with no
	// initial response). Default: 0 (use IdleTimeout for all states).
	AuthIdleTimeout time.Duration

	// AbsoluteSessionTimeout is the maximum total duration of a POP3
	// session regardless of activity. When exceeded, the server sends
	// "-ERR [IN-USE] Maximum session duration exceeded" and closes the
	// connection. This prevents indefinitely-held connections from
	// monopolising server resources. Default: 0 (no absolute limit).
	AbsoluteSessionTimeout time.Duration

	// CommandTimeout is the maximum time allowed for a single command
	// to execute, enforced via context.WithTimeout on the per-command
	// context. Default: 0 (no per-command timeout; the connection-level
	// IdleTimeout still applies).
	CommandTimeout time.Duration

	// WriteTimeout is the maximum time a single write to the client may
	// block. It is applied per underlying write (including each chunk of a
	// streamed RETR/TOP body), so a slow-reading client cannot wedge a
	// response indefinitely. Default: 60s (see defaultWriteTimeout). Set to
	// a negative value to disable (e.g. when a connection wrapper already
	// enforces throughput, such as a min-bytes-per-minute checker).
	WriteTimeout time.Duration

	// InsecureAuth permits USER/PASS and SASL PLAIN authentication over
	// unencrypted connections. When false (default), authentication
	// commands are rejected on non-TLS connections and USER/SASL are
	// not advertised in CAPA.
	InsecureAuth bool

	// MaxLineLength is the maximum length (in bytes) of a client command
	// line. RFC 1939 §4 allows commands up to 255 octets (including
	// CRLF), but real clients sometimes exceed this. Default: 1024.
	MaxLineLength int

	// MaxErrors is the maximum number of client protocol errors before the
	// server disconnects the client. This mitigates brute-force and fuzzing
	// attacks. Default: 10. Set to a negative value (e.g. -1) to disable the
	// limit entirely.
	//
	// A client protocol error is one the library itself detects: an unknown or
	// unsupported command, a malformed or out-of-order command (e.g. PASS
	// before USER), an invalid argument (e.g. a non-numeric message number), a
	// bad SASL payload, or a failed authentication. These are unambiguously
	// client faults and each counts toward the limit.
	//
	// Errors returned by a Session (e.g. RETR of a non-existent message) do
	// NOT count: the library cannot distinguish a client fault from a transient
	// server-side failure, so counting them could disconnect a client for a
	// backend problem. A session that wants a specific error to drop the
	// connection returns &Error{Close: true} (or wraps ErrCloseConnection).
	MaxErrors int

	// AuthFailuresExemptFromMaxErrors, when true, keeps failed Login /
	// AuthenticatePlain attempts from counting toward MaxErrors (the
	// progressive ErrorDelay still applies, and malformed AUTH payloads still
	// count). Embedders whose Session already enforces authentication rate
	// limiting (progressive delays, IP blocking) can set this so a small
	// MaxErrors budget for protocol errors does not disconnect a legitimate
	// user who mistypes a password a couple of times. Default: false (failed
	// authentications count).
	AuthFailuresExemptFromMaxErrors bool

	// ErrorDelay is the base delay applied after a client error (bad
	// login, invalid command). The actual delay is errorCount * ErrorDelay,
	// capped by MaxErrorDelay, and is interruptible by connection shutdown.
	// Default: 0 (no delay).
	ErrorDelay time.Duration

	// MaxErrorDelay caps the progressive per-error delay computed from
	// ErrorDelay. Default: 30s (see defaultMaxErrorDelay). Ignored when
	// ErrorDelay is 0.
	MaxErrorDelay time.Duration

	// Greeting is the text sent after "+OK " in the connection greeting.
	// Default: "POP3 server ready". Consumers typically include a hostname.
	Greeting string

	// RejectMessage is the "-ERR" text sent when NewSession returns a plain
	// (non-*Error) error. Default: "Service not available".
	RejectMessage string

	// StrictSessionErrors, when true, prevents plain (non-*Error) errors
	// returned by Session methods from reaching the client verbatim: the
	// response is replaced with a generic "-ERR internal error" and the
	// original error is logged. Sessions then control the wire message
	// exclusively via *Error. Recommended when session methods may propagate
	// errors from databases or object stores whose text must never leak to
	// clients. Default: false (plain error text is forwarded as-is, per the
	// documented Session contract).
	StrictSessionErrors bool

	// UnknownCommandHandler, if set, is invoked for any command not handled
	// by the built-in dispatcher (in either AUTHORIZATION or TRANSACTION
	// state) before the command is counted against MaxErrors. It lets a
	// consumer add protocol extensions such as Dovecot-style XCLIENT. The
	// handler writes its own response via c.OK / c.Err and may inspect or
	// mutate the live session via c.Session(). It returns handled=true if it
	// consumed the command (suppressing the default "unknown command" error
	// and the MaxErrors increment), and close=true to tear the connection
	// down after the response is flushed.
	UnknownCommandHandler func(ctx context.Context, c *Conn, cmd string, args []string) (handled, close bool)

	// OnCommand, if set, is called after every command completes with the
	// command verb (upper-cased, without arguments so credentials are never
	// exposed), the wall-clock duration, and the session error returned by
	// the handler (nil on success). Intended for metrics and tracing.
	OnCommand func(cmd string, dur time.Duration, err error)

	// OnPanic, if set, is called when a panic escapes a connection's
	// handler goroutine, with the recovered value and the stack. The library
	// always logs the panic and closes the connection regardless.
	OnPanic func(recovered any, stack []byte)

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// defaults returns a copy of the options with zero-value fields replaced
// by their defaults.
func (o *Options) defaults() Options {
	opts := *o

	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 10 * time.Minute
	}
	if opts.MaxLineLength == 0 {
		opts.MaxLineLength = 1024
	}
	if opts.MaxErrors == 0 {
		opts.MaxErrors = 10
	}
	if opts.MaxErrorDelay == 0 {
		opts.MaxErrorDelay = defaultMaxErrorDelay
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = defaultWriteTimeout
	}
	if opts.Greeting == "" {
		opts.Greeting = "POP3 server ready"
	}
	if opts.RejectMessage == "" {
		opts.RejectMessage = "Service not available"
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	return opts
}
