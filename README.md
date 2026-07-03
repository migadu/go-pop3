# go-pop3

A dependency-free POP3 server library for Go, with a matching minimal client
for proxy front-ends. You implement a single `Session` interface for storage and
authentication; the library handles the wire protocol, the RFC 1939 state
machine, dot-stuffing, TLS/STLS, timeouts, and abuse limits.

- Zero dependencies beyond the standard library.
- Streaming `RETR`/`TOP` — bodies are dot-stuffed and CRLF-normalised on the
  fly, never buffered whole.
- Hardened defaults — idle/absolute/write timeouts, line-length caps, a
  per-connection error limit with progressive back-off, panic isolation, and
  CRLF-injection-safe response encoding.
- Extensions — SASL PLAIN, STLS, CAPA, `LANG`/`UTF8`, custom capabilities, and a
  hook for unknown commands (e.g. Dovecot `XCLIENT`).
- Proxy-friendly — `Conn.Hijack()` and the `pop3client` package let a session
  authenticate upstream and relay raw bytes.

## Install

```sh
go get github.com/migadu/go-pop3
```

Requires Go 1.25 or newer.

## Packages

| Package | Purpose |
| --- | --- |
| [`pop3`](./pop3) | Shared wire types (`MessageInfo`, `MessageUidl`, `Capability`). |
| [`pop3server`](./pop3server) | The server: `Server`, `Options`, the `Session` interface, `Conn`, `Error`. |
| [`pop3client`](./pop3client) | Minimal client for proxy front-ends. |
| [`pop3mem`](./pop3mem) | Concurrency-safe in-memory maildrop implementing `Session`; for tests and local dev. |

## Quick start

```go
package main

import (
	"log"

	"github.com/migadu/go-pop3/pop3mem"
	"github.com/migadu/go-pop3/pop3server"
)

func main() {
	store := pop3mem.New()
	store.AddUser("alice", "s3cret")
	store.AddMessage("alice", "uid-0001",
		[]byte("Subject: hello\r\n\r\nHi there.\r\n"))

	srv := pop3server.New(pop3server.Options{
		NewSession:   store.NewSession,
		Greeting:     "example.com POP3 ready",
		InsecureAuth: true, // allow USER/PASS without TLS — development only
	})

	log.Fatal(srv.ListenAndServe(":110"))
}
```

## Implementing a Session

`Options.NewSession` creates one `Session` per connection; the library calls
each method only in the correct protocol state.

```go
type Session interface {
	Close() error

	// AUTHORIZATION state
	Login(ctx context.Context, username, password string) error

	// TRANSACTION state (only after a successful Login)
	Stat(ctx context.Context) (count int, size int64, err error)
	List(ctx context.Context, msg int) ([]pop3.MessageInfo, error)
	Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error)
	Retr(ctx context.Context, msg int) (io.ReadCloser, error)
	Top(ctx context.Context, msg, lines int) (io.ReadCloser, error)
	Dele(ctx context.Context, msg int) error
	Rset(ctx context.Context) error
	Noop(ctx context.Context) error
	Quit(ctx context.Context) (expunged int, err error)
}
```

Key contracts:

- The context carries a per-command deadline when `CommandTimeout` is set;
  propagate it into blocking work so operations abort on disconnect or timeout.
- Deletion is deferred: `Dele` marks, `Quit` commits. If the client drops
  without `QUIT`, `Close` runs without a preceding `Quit`, so do not commit
  pending deletions in `Close`.
- `Retr`/`Top` return an `io.ReadCloser` that the library streams (dot-stuffed,
  CRLF-normalised) and closes. Store messages CRLF-delimited so `Stat`/`List`
  octet counts match the wire form.

`pop3mem/store.go` is a complete reference implementation. Implement
`SessionSASL`, `SessionLang`, or `SessionUTF8` alongside `Session` to have the
library advertise and handle those extensions.

## Error handling

```go
// Plain error: text sent verbatim (unless StrictSessionErrors is set).
return errors.New("mailbox locked")

// *Error: explicit RFC 2449 response code, no internal string leak.
return &pop3server.Error{Code: "AUTH", Message: "authentication failed"}

// Respond, then close the connection.
return &pop3server.Error{Code: "SYS/TEMP", Message: "try later", Close: true}
```

Errors a session returns (e.g. "no such message") do not count toward
`MaxErrors` — the library cannot distinguish a client fault from a transient
backend failure. Errors the library detects (bad syntax, invalid arguments,
wrong-order or unknown commands, failed auth) do count.

## TLS

```go
srv := pop3server.New(pop3server.Options{
	NewSession: store.NewSession,
	TLSConfig:  &tls.Config{Certificates: []tls.Certificate{cert}},
	// InsecureAuth left false: auth is refused (and unadvertised) until secured.
})

go srv.ListenAndServeTLS(":995") // implicit TLS
go srv.ListenAndServe(":110")    // STLS upgrade advertised via CAPA
```

`ListenAndServe` does not wrap the listener in TLS even when `TLSConfig` is set;
use `ListenAndServeTLS` for implicit-TLS ports, or wrap your own listener with
`tls.NewListener` and call `Serve`.

## Configuration

Defaults are applied; every field is optional.

| Option | Default | Purpose |
| --- | --- | --- |
| `IdleTimeout` | 10m | Max wait for the next command. |
| `AuthIdleTimeout` | 0 (uses `IdleTimeout`) | Shorter idle limit while unauthenticated. |
| `AbsoluteSessionTimeout` | 0 (off) | Hard cap on total session duration. |
| `CommandTimeout` | 0 (off) | Per-command deadline via context. |
| `WriteTimeout` | 60s | Per-write deadline; bounds slow-reader stalls. |
| `MaxLineLength` | 1024 | Command-line length cap. |
| `MaxErrors` | 10 | Client protocol errors before disconnect (`-1` disables). |
| `ErrorDelay` / `MaxErrorDelay` | 0 / 30s | Progressive, interruptible back-off after each error. |
| `InsecureAuth` | false | Permit auth on plaintext connections. |
| `StrictSessionErrors` | false | Replace plain session-error text with a generic message. |

Hooks: `UnknownCommandHandler`, `OnCommand` (verb only, never credentials),
`OnPanic`, and a structured `Logger` (`slog`).

Connection concurrency is not capped internally. For a hard limit, wrap the
listener with `golang.org/x/net/netutil.LimitListener`; for a graceful
rejection, return an `*Error` from `NewSession`.

## Proxy front-ends

A session may authenticate upstream and take over the raw connection instead of
entering the TRANSACTION state. Call `Conn.Hijack()` from `Login` /
`AuthenticatePlain` to obtain the `net.Conn` and buffered reader (preserving
pipelined bytes), dial the backend with `pop3client`, and relay both directions.
See `pop3client/proxy_test.go` for a complete example.

## Standards

Implements POP3 (RFC 1939) with the extension mechanism of RFC 2449 (`CAPA`,
`RESP-CODES`, `PIPELINING`), `STLS` (RFC 2595), SASL `AUTH`/PLAIN (RFC 5034 /
RFC 4616), and `LANG`/`UTF8` (RFC 6856). The obsolete `LAST` command is rejected
without penalty for legacy-probing clients.

## Testing

```sh
go test ./...
go test -race ./...
```

## License

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 Migadu-Mail GmbH.
