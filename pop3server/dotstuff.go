package pop3server

import (
	"bytes"
	"io"
)

// dotStuffWriter is an io.Writer that applies POP3 byte-stuffing (RFC 1939 §3)
// to lines beginning with '.', normalises line endings to CRLF, and appends the
// terminating ".\r\n" sequence when Close is called. It is used to stream
// message bodies (RETR, TOP) to the client without materialising the entire
// body in memory.
//
// Only LF is treated as a line terminator: a bare LF is normalised to CRLF
// (one extra output octet), while a lone CR (not followed by LF) is message
// content and passes through verbatim — it neither breaks the line nor makes
// a following '.' eligible for stuffing. This keeps the output size exactly
// len(body) + count(bare LFs), so an embedding server can announce the octet
// count without transforming the body first.
//
// Usage:
//
//	dsw := newDotStuffWriter(conn)
//	io.Copy(dsw, messageBodyReader)
//	dsw.Close() // writes ".\r\n"
type dotStuffWriter struct {
	w           io.Writer
	atLineStart bool // true when the next byte is at the start of a line
	scratch     [1]byte
	lastByte    byte // tracks the previous byte for CRLF normalisation
}

// newDotStuffWriter creates a new dot-stuffing writer that wraps w.
func newDotStuffWriter(w io.Writer) *dotStuffWriter {
	return &dotStuffWriter{
		w:           w,
		atLineStart: true, // first byte of the stream is at line start
	}
}

// Write applies dot-stuffing and CRLF normalisation to p, writing the
// transformed bytes to the underlying writer.
//
// A single input byte can expand to several output bytes (a normalised CRLF, a
// stuffed dot). On a downstream write error Write returns the number of input
// bytes it fully processed — a byte is only counted once all of its output has
// been written — so the io.Writer contract (n < len(p) implies a non-nil
// error) holds.
func (d *dotStuffWriter) Write(p []byte) (int, error) {
	vectorScan := true
	for i := 0; i < len(p); {
		b := p[i]
		// Normal CRLF data can pass through unchanged, including multiple
		// lines. Stop only at a bare LF or a dot needing an extra byte.
		if b != '\n' && !(d.atLineStart && b == '.') {
			end := i
			// Skip validated vector blocks where supported; preserve the
			// scalar handling of the first byte and all exceptional data.
			if vectorScan && len(p)-i >= 32 {
				skipped := ordinaryPrefix(p[i:])
				// Once a block contains exceptional data, use the scalar
				// scanner for the rest of this Write. Repeated bare LFs or
				// leading dots should not pay for two scans of every line.
				vectorScan = skipped >= len(p)-i-16
				end += skipped
			}
			for end < len(p) {
				newline := bytes.IndexByte(p[end:], '\n')
				if newline < 0 {
					end = len(p)
					break
				}
				newline += end
				if newline == i || p[newline-1] != '\r' {
					end = newline
					break
				}
				end = newline + 1
				if end < len(p) && p[end] == '.' {
					break
				}
			}
			if end > i {
				n, err := d.w.Write(p[i:end])
				if n > 0 {
					d.lastByte = p[i+n-1]
					d.atLineStart = d.lastByte == '\n'
					i += n
				}
				if err != nil {
					return i, err
				}
				if i != end {
					return i, io.ErrShortWrite
				}
				continue
			}
		}

		switch {
		case b == '\n':
			// Normalise to CRLF. If the previous byte was '\r',
			// we already wrote '\r', so just write '\n'.
			if d.lastByte != '\r' {
				if err := d.writeByte('\r'); err != nil {
					return i, err
				}
			}
			if err := d.writeByte('\n'); err != nil {
				return i, err
			}
			d.atLineStart = true

		case b == '\r':
			// Write the \r but don't mark line start yet — if the next
			// byte is '\n' this is a CRLF pair; otherwise it was a lone
			// CR, which is content, not a line terminator.
			if err := d.writeByte('\r'); err != nil {
				return i, err
			}
			d.atLineStart = false

		default:
			// Dot-stuff: if we're at line start and the byte is '.', prepend '.'.
			if d.atLineStart && b == '.' {
				if err := d.writeByte('.'); err != nil {
					return i, err
				}
			}
			if err := d.writeByte(b); err != nil {
				return i, err
			}
			d.atLineStart = false
		}

		d.lastByte = b
		i++
	}
	return len(p), nil
}

// Reuse storage for inserted bytes instead of allocating once per byte.
func (d *dotStuffWriter) writeByte(b byte) error {
	d.scratch[0] = b
	n, err := d.w.Write(d.scratch[:])
	if err == nil && n != 1 {
		return io.ErrShortWrite
	}
	return err
}

// Close writes the terminating CRLF (if the last line didn't end with one)
// and the ".\r\n" sequence. It does NOT close the underlying writer.
func (d *dotStuffWriter) Close() error {
	// Ensure the last line is terminated with CRLF before the dot.
	if !d.atLineStart {
		// A stream ending on a bare CR already emitted the '\r' (atLineStart
		// stays false until the following '\n' arrives); complete it to a
		// single CRLF with just '\n' rather than emitting "\r\n" and leaving a
		// stray CR. Any other unterminated line gets a full CRLF.
		term := "\r\n"
		if d.lastByte == '\r' {
			term = "\n"
		}
		if _, err := d.w.Write([]byte(term)); err != nil {
			return err
		}
	}
	_, err := d.w.Write([]byte(".\r\n"))
	return err
}
