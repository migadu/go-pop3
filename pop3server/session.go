package pop3server

import (
	"context"
	"io"

	"github.com/migadu/go-pop3/pop3"
)

// Session is a POP3 session for a single client connection.
//
// Implementations provide the business logic (authentication, message
// retrieval from a store, deletion, etc.) while the library handles
// protocol parsing, response formatting, state machine enforcement,
// and per-command context management.
//
// The context passed to every method is derived from the connection
// context and carries a per-command deadline when command timeouts are
// configured. Implementations should propagate it into blocking work
// (database queries, object-storage reads, etc.) so that in-flight
// operations are abandoned when the client disconnects or a timeout
// fires.
//
// # POP3 state machine
//
// The library enforces the RFC 1939 state transitions:
//
//	AUTHORIZATION  →  Login / Authenticate succeed  →  TRANSACTION
//	TRANSACTION    →  QUIT                          →  UPDATE (commit deletes)
//
// Methods are only called in the appropriate state; the library returns
// -ERR to the client for out-of-state commands without invoking the
// session.
type Session interface {
	// Close is called when the connection is torn down (client disconnect,
	// timeout, or server shutdown). It is always called exactly once,
	// regardless of whether the session was authenticated. Implementations
	// should release any resources (locks, DB connections, etc.) here.
	//
	// If the client disconnects without QUIT, Close is called without a
	// preceding Quit — so pending deletions should NOT be committed in Close.
	Close() error

	// --- AUTHORIZATION state ---

	// Login authenticates a user with USER/PASS credentials. The library
	// calls this after receiving both USER and PASS commands. Return nil
	// on success; the library transitions the connection to TRANSACTION
	// state automatically.
	//
	// Return an error to reject authentication. A plain error's text is
	// sent verbatim as the -ERR message; return an *Error to control the
	// response code/message (and avoid leaking internal error strings), or
	// wrap ErrCloseConnection / return &Error{Close: true} to drop the
	// connection after the response (e.g. when a rate limiter blocks the
	// attempt).
	//
	// A proxy implementation may call conn.Hijack() from within Login to
	// take over the raw connection instead of entering TRANSACTION state.
	Login(ctx context.Context, username, password string) error

	// --- TRANSACTION state ---
	// All methods below are only called after a successful Login.

	// Stat returns the number of messages and total size in octets of the
	// maildrop. Corresponds to the STAT command (RFC 1939 §5).
	Stat(ctx context.Context) (count int, size int64, err error)

	// List returns message metadata. If msg > 0, returns info for that
	// single message (or an error if it doesn't exist / is deleted).
	// If msg == 0, returns info for all non-deleted messages.
	// Corresponds to the LIST command (RFC 1939 §5).
	List(ctx context.Context, msg int) ([]pop3.MessageInfo, error)

	// Uidl returns unique-id listings. If msg > 0, returns the unique-id
	// for that single message. If msg == 0, returns unique-ids for all
	// non-deleted messages. Corresponds to the UIDL command (RFC 1939 §7).
	Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error)

	// Retr retrieves the full message body for the given message number.
	// The returned ReadCloser is consumed by the library and sent to the
	// client with dot-stuffing applied. The library closes the reader
	// after transmission. Corresponds to the RETR command (RFC 1939 §5).
	//
	// The library normalises line endings to CRLF and dot-stuffs the stream
	// as it sends it, so the number of octets on the wire may exceed the size
	// reported by Stat/List (which is the stored message size). RFC 1939
	// treats the listed size as approximate, but for the closest agreement
	// store messages with CRLF line endings. The reader should yield the same
	// bytes each time so RETR and TOP stay consistent.
	Retr(ctx context.Context, msg int) (io.ReadCloser, error)

	// Top retrieves the message headers and the first n lines of the body.
	// Similar to Retr but the session is responsible for truncation.
	// Corresponds to the TOP command (RFC 1939 §7).
	Top(ctx context.Context, msg int, lines int) (io.ReadCloser, error)

	// Dele marks a message for deletion. The message is not actually
	// removed until Quit is called. Corresponds to the DELE command
	// (RFC 1939 §5).
	Dele(ctx context.Context, msg int) error

	// Rset unmarks all messages that have been marked for deletion.
	// Corresponds to the RSET command (RFC 1939 §5).
	Rset(ctx context.Context) error

	// Noop does nothing. Corresponds to the NOOP command (RFC 1939 §5).
	Noop(ctx context.Context) error

	// Quit commits all pending deletions and returns the number of
	// messages actually expunged. This is called when the client sends
	// QUIT in the TRANSACTION state. If an error is returned, the
	// library sends -ERR and the deletions are NOT committed (per RFC
	// 1939 §6: "If there is an error ... the POP3 server MUST NOT
	// delete any messages").
	Quit(ctx context.Context) (expunged int, err error)
}

// SessionSASL may be implemented by a Session to support SASL
// authentication mechanisms. The library probes for this interface via type
// assertion and advertises the mechanisms in CAPA / AUTH.
//
// The library implements the wire exchange for the PLAIN mechanism only.
// AuthenticateMechanisms should therefore return ["PLAIN"]; any other
// mechanism a client requests is rejected with -ERR even if advertised.
type SessionSASL interface {
	Session

	// AuthenticateMechanisms returns the list of SASL mechanisms
	// advertised for this session. In practice this is ["PLAIN"].
	AuthenticateMechanisms() []string

	// Authenticate performs SASL authentication for the given mechanism.
	// The library handles the AUTH command exchange and base64
	// encoding/decoding; the session receives the decoded credentials.
	//
	// For SASL PLAIN, initialResponse contains the decoded
	// \x00authzid\x00authcid\x00password payload.
	AuthenticatePlain(ctx context.Context, identity, username, password string) error
}

// SessionLang may be implemented to support the LANG extension (RFC 6856).
type SessionLang interface {
	Session

	// SetLanguage sets the preferred language for server responses.
	// Returns the language tag actually selected.
	SetLanguage(ctx context.Context, lang string) (string, error)

	// ListLanguages returns the available languages.
	ListLanguages(ctx context.Context) ([]LanguageInfo, error)
}

// LanguageInfo describes an available language for the LANG extension.
type LanguageInfo struct {
	Tag         string // IETF language tag (e.g. "en", "de")
	Description string // Human-readable description
}

// SessionUTF8 may be implemented to support the UTF8 extension (RFC 6856).
type SessionUTF8 interface {
	Session

	// EnableUTF8 enables UTF-8 mode for the session. After this call,
	// the server accepts and returns UTF-8 encoded headers.
	EnableUTF8(ctx context.Context) error
}
