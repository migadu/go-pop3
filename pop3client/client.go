// Package pop3client is a minimal POP3 client for connecting to an upstream
// POP3 server. It is intended for proxy front-ends: after connecting,
// (optionally) forwarding client identity via XCLIENT, and authenticating,
// the caller takes over the raw connection and buffered reader to relay bytes
// bidirectionally between the downstream client and this upstream connection.
//
// All network operations honour both the deadline and the cancellation of
// the context passed to them: a deadline is applied to the socket, and a
// cancellation forces the in-flight read/write to unblock immediately. After
// a cancellation the Client is no longer usable and must be Closed. Line
// reads are bounded by Options.MaxLineLength; multi-line responses by
// Options.MaxResponseLines.
package pop3client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"
)

// Options configures a Client.
type Options struct {
	// TLSConfig, when set, enables TLS. With STARTTLS false the connection is
	// TLS from the start (implicit TLS). With STARTTLS true the client
	// connects in plaintext, reads the greeting, issues STLS and upgrades.
	TLSConfig *tls.Config

	// STARTTLS selects the STLS upgrade path (see TLSConfig).
	STARTTLS bool

	// MaxLineLength bounds a single response line, so a server that never
	// sends a newline cannot grow the read buffer without limit. Default 4096.
	MaxLineLength int

	// MaxResponseLines bounds the number of lines accepted in a multi-line
	// response (CAPA, LIST, UIDL), so a misbehaving server cannot grow the
	// result without limit. Default 100000.
	MaxResponseLines int

	// Dialer, when set, establishes the TCP connection. Use it to bind a
	// source address, set keep-alive, emit PROXY-protocol via a custom
	// DialContext, etc. Default: &net.Dialer{}.
	Dialer *net.Dialer
}

// Client is a POP3 client connection.
type Client struct {
	conn         net.Conn
	reader       *bufio.Reader
	writer       *bufio.Writer
	maxLine      int
	maxRespLines int
	greeting     string
}

// XClientParam is a single Dovecot-style XCLIENT attribute (e.g. ADDR, PORT,
// LOGIN, SESSION).
type XClientParam struct {
	Name  string
	Value string
}

// ProtocolError reports an unexpected (non-"+OK") response from the server.
type ProtocolError struct {
	// Response is the offending server response line.
	Response string
}

func (e *ProtocolError) Error() string {
	return "pop3client: unexpected response: " + e.Response
}

// Dial connects to addr and completes the greeting (and, when configured, the
// implicit-TLS handshake or STLS upgrade). The returned Client is ready for
// CAPA/XCLIENT/AUTH before hand-off to a relay.
func Dial(ctx context.Context, addr string, opts Options) (*Client, error) {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	maxLine := opts.MaxLineLength
	if maxLine <= 0 {
		maxLine = 4096
	}
	maxRespLines := opts.MaxResponseLines
	if maxRespLines <= 0 {
		maxRespLines = 100_000
	}

	conn := rawConn

	// Implicit TLS: wrap before reading the greeting.
	if opts.TLSConfig != nil && !opts.STARTTLS {
		tconn := tls.Client(rawConn, opts.TLSConfig)
		if dl, ok := ctx.Deadline(); ok {
			_ = tconn.SetDeadline(dl)
		}
		if err := tconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		conn = tconn
	}

	c := &Client{
		conn:         conn,
		reader:       bufio.NewReader(conn),
		writer:       bufio.NewWriter(conn),
		maxLine:      maxLine,
		maxRespLines: maxRespLines,
	}

	// Make the greeting read and any STLS upgrade interruptible by ctx
	// cancellation (the deadline, when set, is applied per read/write).
	stop := c.guard(ctx)
	defer stop()

	greeting, err := c.readLine(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !isOK(greeting) {
		conn.Close()
		return nil, &ProtocolError{Response: greeting}
	}
	c.greeting = greeting

	// STLS upgrade path.
	if opts.TLSConfig != nil && opts.STARTTLS {
		if err := c.startTLS(ctx, opts.TLSConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return c, nil
}

// Greeting returns the server's greeting line (including the "+OK" prefix).
func (c *Client) Greeting() string { return c.greeting }

// Conn returns the underlying net.Conn. After authentication, the caller
// typically clears deadlines (conn.SetDeadline(time.Time{})) and relays bytes
// between this conn and the downstream client.
func (c *Client) Conn() net.Conn { return c.conn }

// Reader returns the buffered reader over the connection. It may already hold
// bytes read ahead from the server; a relay must drain it before reading the
// raw conn so no server data is lost.
func (c *Client) Reader() *bufio.Reader { return c.reader }

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// Capa issues CAPA and returns the advertised capability lines.
func (c *Client) Capa(ctx context.Context) ([]string, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, "CAPA"); err != nil {
		return nil, err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return nil, err
	}
	if !isOK(status) {
		return nil, &ProtocolError{Response: status}
	}
	return c.readMultiLine(ctx)
}

// XClient sends a Dovecot-style XCLIENT command forwarding downstream client
// identity to the upstream server and expects "+OK". Example:
//
//	client.XClient(ctx,
//	    pop3client.XClientParam{Name: "ADDR", Value: "203.0.113.7"},
//	    pop3client.XClientParam{Name: "PORT", Value: "51000"},
//	    pop3client.XClientParam{Name: "LOGIN", Value: "user@example.com"})
func (c *Client) XClient(ctx context.Context, params ...XClientParam) error {
	defer c.guard(ctx)()
	var b strings.Builder
	b.WriteString("XCLIENT")
	for _, p := range params {
		b.WriteByte(' ')
		b.WriteString(p.Name)
		b.WriteByte('=')
		b.WriteString(p.Value)
	}
	if err := c.writeCmd(ctx, b.String()); err != nil {
		return err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}
	return nil
}

// AuthPlain authenticates with SASL PLAIN, sending the initial response on the
// AUTH line. identity may be empty (the common case).
func (c *Client) AuthPlain(ctx context.Context, identity, username, password string) error {
	defer c.guard(ctx)()
	payload := identity + "\x00" + username + "\x00" + password
	enc := base64.StdEncoding.EncodeToString([]byte(payload))
	if err := c.writeCmd(ctx, "AUTH PLAIN "+enc); err != nil {
		return err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}
	return nil
}

// User authenticates with USER/PASS, expecting "+OK" for each step.
func (c *Client) User(ctx context.Context, username, password string) error {
	if err := c.cmdExpectOK(ctx, "USER "+username); err != nil {
		return err
	}
	return c.cmdExpectOK(ctx, "PASS "+password)
}

// Cmd sends a single command line and returns the server's single-line status
// response verbatim (including "+OK"/"-ERR"). It does not read multi-line
// bodies; use Reader for that.
func (c *Client) Cmd(ctx context.Context, line string) (string, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, line); err != nil {
		return "", err
	}
	return c.readLine(ctx)
}

// Quit sends QUIT and expects "+OK".
func (c *Client) Quit(ctx context.Context) error {
	return c.cmdExpectOK(ctx, "QUIT")
}

// --- internal helpers ---

// guard makes the current operation interruptible by ctx *cancellation* (a
// ctx *deadline* is already applied to the socket by readLine/writeCmd): if
// ctx is cancelled while the operation is in flight, the connection deadline
// is forced into the past, unblocking any blocked read or write with a
// timeout error. The returned stop function must be called when the
// operation completes; nesting guards is harmless.
//
// The conn is captured at guard creation: even after an STLS upgrade,
// poisoning the deadline of the underlying conn unblocks reads on the TLS
// layer above it.
func (c *Client) guard(ctx context.Context) (stop func()) {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	conn := c.conn
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now().Add(-time.Second))
		case <-done:
		}
	}()
	return func() { close(done) }
}

func (c *Client) startTLS(ctx context.Context, cfg *tls.Config) error {
	if err := c.cmdExpectOK(ctx, "STLS"); err != nil {
		return err
	}
	tconn := tls.Client(c.conn, cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = tconn.SetDeadline(dl)
	}
	if err := tconn.HandshakeContext(ctx); err != nil {
		return err
	}
	c.conn = tconn
	// Fresh reader/writer over the TLS conn; any plaintext buffered after the
	// "+OK" STLS response is discarded (guards against STLS response injection).
	c.reader = bufio.NewReader(tconn)
	c.writer = bufio.NewWriter(tconn)
	return nil
}

func (c *Client) cmdExpectOK(ctx context.Context, line string) error {
	status, err := c.Cmd(ctx, line)
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}
	return nil
}

func (c *Client) writeCmd(ctx context.Context, line string) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(dl)
	}
	if _, err := c.writer.WriteString(line + "\r\n"); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *Client) readLine(ctx context.Context) (string, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(dl)
	}
	var line []byte
	for {
		chunk, isPrefix, err := c.reader.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > c.maxLine {
			return "", errors.New("pop3client: response line too long")
		}
		if !isPrefix {
			break
		}
	}
	return string(line), nil
}

// readMultiLine reads a dot-terminated multi-line response, unstuffing leading
// dots. It bounds the number of lines (Options.MaxResponseLines) to avoid
// unbounded memory growth.
func (c *Client) readMultiLine(ctx context.Context) ([]string, error) {
	var lines []string
	for {
		line, err := c.readLine(ctx)
		if err != nil {
			return nil, err
		}
		if line == "." {
			return lines, nil
		}
		lines = append(lines, unstuffLine(line))
		if len(lines) > c.maxRespLines {
			return nil, errors.New("pop3client: multi-line response too long")
		}
	}
}

// SetDeadline sets the read/write deadline on the underlying connection. Pass
// the zero Time to clear deadlines before entering a relay.
func (c *Client) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func isOK(line string) bool { return strings.HasPrefix(line, "+OK") }
