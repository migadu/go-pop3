package pop3server

import "io"

// SizedBody wraps a message body with the exact octet count to announce in the
// RETR success response ("+OK nn octets", RFC 1939 §5). The count must be the
// CRLF-normalized size of the payload BEFORE dot-stuffing — i.e. the number of
// octets the client reconstructs after un-stuffing — so byte-counting clients
// stay in sync with the stream.
//
// Sessions that cannot cheaply compute the normalized size can return the body
// unwrapped; the library then replies "+OK Message follows", which RFC 1939
// permits (the octet count in the response is optional).
func SizedBody(body io.ReadCloser, octets int64) io.ReadCloser {
	return &sizedBody{ReadCloser: body, octets: octets}
}

type sizedBody struct {
	io.ReadCloser
	octets int64
}
