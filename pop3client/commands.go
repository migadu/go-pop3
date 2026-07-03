package pop3client

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/migadu/go-pop3/pop3"
)

// Stat issues STAT and returns the message count and total maildrop size.
func (c *Client) Stat(ctx context.Context) (count int, size int64, err error) {
	status, err := c.Cmd(ctx, "STAT")
	if err != nil {
		return 0, 0, err
	}
	if !isOK(status) {
		return 0, 0, &ProtocolError{Response: status}
	}
	// "+OK <count> <size>"
	fields := strings.Fields(status)
	if len(fields) < 3 {
		return 0, 0, &ProtocolError{Response: status}
	}
	count, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, &ProtocolError{Response: status}
	}
	size, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return 0, 0, &ProtocolError{Response: status}
	}
	return count, size, nil
}

// List issues "LIST" and returns metadata for all non-deleted messages.
func (c *Client) List(ctx context.Context) ([]pop3.MessageInfo, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, "LIST"); err != nil {
		return nil, err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return nil, err
	}
	if !isOK(status) {
		return nil, &ProtocolError{Response: status}
	}
	lines, err := c.readMultiLine(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]pop3.MessageInfo, 0, len(lines))
	for _, line := range lines {
		num, size, err := parseNumSize(line)
		if err != nil {
			return nil, err
		}
		items = append(items, pop3.MessageInfo{Num: num, Size: size})
	}
	return items, nil
}

// ListOne issues "LIST <msg>" and returns metadata for a single message.
func (c *Client) ListOne(ctx context.Context, msg int) (pop3.MessageInfo, error) {
	status, err := c.Cmd(ctx, fmt.Sprintf("LIST %d", msg))
	if err != nil {
		return pop3.MessageInfo{}, err
	}
	if !isOK(status) {
		return pop3.MessageInfo{}, &ProtocolError{Response: status}
	}
	// "+OK <num> <size>"
	num, size, err := parseNumSize(strings.TrimSpace(strings.TrimPrefix(status, "+OK")))
	if err != nil {
		return pop3.MessageInfo{}, &ProtocolError{Response: status}
	}
	return pop3.MessageInfo{Num: num, Size: size}, nil
}

// Uidl issues "UIDL" and returns unique-ids for all non-deleted messages.
func (c *Client) Uidl(ctx context.Context) ([]pop3.MessageUidl, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, "UIDL"); err != nil {
		return nil, err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return nil, err
	}
	if !isOK(status) {
		return nil, &ProtocolError{Response: status}
	}
	lines, err := c.readMultiLine(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]pop3.MessageUidl, 0, len(lines))
	for _, line := range lines {
		num, uid, err := parseNumUID(line)
		if err != nil {
			return nil, err
		}
		items = append(items, pop3.MessageUidl{Num: num, UniqueID: uid})
	}
	return items, nil
}

// UidlOne issues "UIDL <msg>" and returns the unique-id of a single message.
func (c *Client) UidlOne(ctx context.Context, msg int) (pop3.MessageUidl, error) {
	status, err := c.Cmd(ctx, fmt.Sprintf("UIDL %d", msg))
	if err != nil {
		return pop3.MessageUidl{}, err
	}
	if !isOK(status) {
		return pop3.MessageUidl{}, &ProtocolError{Response: status}
	}
	num, uid, err := parseNumUID(strings.TrimSpace(strings.TrimPrefix(status, "+OK")))
	if err != nil {
		return pop3.MessageUidl{}, &ProtocolError{Response: status}
	}
	return pop3.MessageUidl{Num: num, UniqueID: uid}, nil
}

// Retr issues "RETR <msg>" and returns a reader over the message body with
// dot-stuffing removed. The caller MUST read to EOF and Close the reader
// before issuing another command, so the connection is left in a clean state.
func (c *Client) Retr(ctx context.Context, msg int) (io.ReadCloser, error) {
	return c.retrieve(ctx, fmt.Sprintf("RETR %d", msg))
}

// Top issues "TOP <msg> <lines>" and returns a reader over the headers plus
// the first n body lines (dot-stuffing removed). Same read/close contract as
// Retr.
func (c *Client) Top(ctx context.Context, msg, lines int) (io.ReadCloser, error) {
	return c.retrieve(ctx, fmt.Sprintf("TOP %d %d", msg, lines))
}

func (c *Client) retrieve(ctx context.Context, cmd string) (io.ReadCloser, error) {
	// One guard spans the whole retrieval (status + streamed body) so ctx
	// cancellation unblocks a read at any point; the bodyReader releases it
	// when the terminating "." is seen or the reader is closed.
	stop := c.guard(ctx)
	if err := c.writeCmd(ctx, cmd); err != nil {
		stop()
		return nil, err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		stop()
		return nil, err
	}
	if !isOK(status) {
		stop()
		return nil, &ProtocolError{Response: status}
	}
	return &bodyReader{c: c, ctx: ctx, stop: stop}, nil
}

// Dele issues "DELE <msg>".
func (c *Client) Dele(ctx context.Context, msg int) error {
	return c.cmdExpectOK(ctx, fmt.Sprintf("DELE %d", msg))
}

// Rset issues "RSET", unmarking all messages marked for deletion.
func (c *Client) Rset(ctx context.Context) error { return c.cmdExpectOK(ctx, "RSET") }

// Noop issues "NOOP".
func (c *Client) Noop(ctx context.Context) error { return c.cmdExpectOK(ctx, "NOOP") }

// bodyReader streams a dot-terminated, dot-stuffed multi-line response as the
// reconstructed message bytes (CRLF line endings, leading dots unstuffed).
type bodyReader struct {
	c    *Client
	ctx  context.Context
	buf  []byte
	done bool
	stop func() // releases the cancellation guard armed in retrieve
}

// finish marks the body as fully consumed (or failed) and releases the
// cancellation guard exactly once.
func (b *bodyReader) finish() {
	b.done = true
	if b.stop != nil {
		b.stop()
		b.stop = nil
	}
}

func (b *bodyReader) Read(p []byte) (int, error) {
	for len(b.buf) == 0 {
		if b.done {
			return 0, io.EOF
		}
		line, err := b.c.readLine(b.ctx)
		if err != nil {
			b.finish()
			return 0, err
		}
		if line == "." {
			b.finish()
			return 0, io.EOF
		}
		b.buf = append([]byte(unstuffLine(line)), '\r', '\n')
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

// Close drains any unread body lines so the connection can be reused.
func (b *bodyReader) Close() error {
	for !b.done {
		line, err := b.c.readLine(b.ctx)
		if err != nil {
			b.finish()
			return err
		}
		if line == "." {
			b.finish()
		}
	}
	b.finish() // no-op when already finished; releases the guard otherwise
	return nil
}

// unstuffLine removes a single leading '.' that the server added for
// dot-stuffing (RFC 1939 §3). The lone "." terminator is handled by the caller.
func unstuffLine(line string) string {
	if strings.HasPrefix(line, ".") {
		return line[1:]
	}
	return line
}

func parseNumSize(line string) (num int, size int64, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("pop3client: malformed LIST line %q", line)
	}
	num, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, fmt.Errorf("pop3client: malformed LIST line %q", line)
	}
	size, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("pop3client: malformed LIST line %q", line)
	}
	return num, size, nil
}

func parseNumUID(line string) (num int, uid string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, "", fmt.Errorf("pop3client: malformed UIDL line %q", line)
	}
	num, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", fmt.Errorf("pop3client: malformed UIDL line %q", line)
	}
	return num, fields[1], nil
}
