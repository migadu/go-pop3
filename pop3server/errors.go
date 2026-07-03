package pop3server

import (
	"errors"
	"strings"
)

// ErrCloseConnection may be returned (or wrapped, via fmt.Errorf("%w", ...))
// by a Session method to instruct the library to send the error's -ERR
// response and then close the connection. Use it to implement "respond then
// drop" behaviour (e.g. when a rate limiter blocks an authentication attempt)
// without leaving the session open.
//
// When ErrCloseConnection is returned bare, a generic "internal error" text
// is sent to the client. To control the wire message, return an *Error with
// Close set to true instead.
var ErrCloseConnection = errors.New("pop3server: close connection")

// Error is a Session error whose response is sent verbatim to the client and
// which can request connection closure. Unlike a plain error (whose text is
// forwarded as-is), an *Error gives the session explicit control over the
// POP3 response code and message and guarantees no internal error string
// leaks onto the wire.
//
//	return &pop3server.Error{Code: "AUTH", Message: "authentication failed"}
//	// wire: -ERR [AUTH] authentication failed
//
//	return &pop3server.Error{Code: "SYS/TEMP", Message: "try again later", Close: true}
//	// wire: -ERR [SYS/TEMP] try again later  (then the connection is closed)
type Error struct {
	// Code is the optional RFC 2449 extended response code, without
	// brackets (e.g. "AUTH", "SYS/TEMP", "IN-USE"). Empty for no code.
	Code string

	// Message is the human-readable message. If empty, "internal error"
	// is used so nothing sensitive is ever emitted by default.
	Message string

	// Close, when true, causes the connection to be closed after the
	// response is flushed.
	Close bool
}

// Error implements the error interface.
func (e *Error) Error() string { return e.wireMessage() }

// wireMessage renders the text that follows "-ERR " on the wire.
func (e *Error) wireMessage() string {
	msg := e.Message
	if msg == "" {
		msg = "internal error"
	}
	if e.Code == "" {
		return msg
	}
	return "[" + strings.ToUpper(e.Code) + "] " + msg
}
