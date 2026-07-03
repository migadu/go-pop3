// Package pop3 defines the protocol-level types used by a POP3 server
// and its session implementations.
//
// It is intentionally kept minimal — only wire-level types that both the
// library and consumers need to share live here.
package pop3

// MessageInfo carries the metadata returned by the LIST command:
// the 1-based message number and the size in octets.
type MessageInfo struct {
	Num  int   // 1-based message number in the maildrop
	Size int64 // Message size in octets (RFC 1939 §7, LIST)
}

// MessageUidl carries the metadata returned by the UIDL command:
// the 1-based message number and a server-assigned unique-id.
type MessageUidl struct {
	Num      int    // 1-based message number in the maildrop
	UniqueID string // Unique-id (RFC 1939 §7, UIDL)
}

// Capability represents a single capability line returned by the CAPA
// command (RFC 2449 §6).
//
//	CAPA
//	+OK Capability list follows
//	TOP
//	UIDL
//	SASL PLAIN LOGIN
//	.
//
// The Name is "SASL", Params is ["PLAIN", "LOGIN"].
type Capability struct {
	Name   string   // Capability name (e.g. "TOP", "SASL", "UIDL")
	Params []string // Optional parameters (e.g. mechanism names for SASL)
}
