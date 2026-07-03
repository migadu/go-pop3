// Package pop3mem is a small, dependency-free in-memory POP3 maildrop that
// implements the pop3server.Session interface. It is intended for tests,
// examples, and local development against a server built with this library.
//
// A Store holds users and their messages. Store.NewSession can be used
// directly as pop3server.Options.NewSession:
//
//	store := pop3mem.New()
//	store.AddUser("user", "pass")
//	store.AddMessage("user", "uid-1", []byte("Subject: hi\r\n\r\nhello\r\n"))
//
//	srv := pop3server.New(pop3server.Options{
//	    NewSession:   store.NewSession,
//	    InsecureAuth: true,
//	})
//
// Semantics follow RFC 1939: a session snapshots the maildrop at login,
// DELE marks messages for deletion within the session, RSET clears the marks,
// and QUIT expunges the marked messages from the store.
package pop3mem

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// Message is a stored message: a server-assigned unique id and the raw bytes
// (headers + body, CRLF-delimited).
type Message struct {
	UID  string
	Data []byte
}

// Store is an in-memory multi-user maildrop. It is safe for concurrent use.
type Store struct {
	mu    sync.Mutex
	users map[string]*account
}

type account struct {
	password string
	messages []*Message
}

// New returns an empty Store.
func New() *Store {
	return &Store{users: make(map[string]*account)}
}

// AddUser creates (or replaces) a user with the given password.
func (s *Store) AddUser(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[username] = &account{password: password}
}

// AddMessage appends a message to the user's maildrop. It returns an error if
// the user does not exist.
func (s *Store) AddMessage(username, uid string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.users[username]
	if !ok {
		return fmt.Errorf("pop3mem: unknown user %q", username)
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	acc.messages = append(acc.messages, &Message{UID: uid, Data: cp})
	return nil
}

// NewSession implements pop3server.Options.NewSession, returning a fresh
// unauthenticated session bound to this store.
func (s *Store) NewSession(_ *pop3server.Conn) (pop3server.Session, error) {
	return &session{store: s, deleted: make(map[int]bool)}, nil
}

// dummyPassword is compared against when the supplied username is unknown, so
// authenticate performs a password comparison on every call and does not
// return measurably faster for a non-existent user (mitigating account
// enumeration by timing).
const dummyPassword = "\x00pop3mem-nonexistent-account\x00"

// authenticate verifies credentials and returns a snapshot of the user's
// messages.
//
// It runs a constant-time password comparison whether or not the user exists,
// so the response time does not reveal which usernames are valid. Note that
// pop3mem stores plaintext passwords for simplicity: a production Session
// should verify against a slow password hash (bcrypt/argon2), whose fixed
// verification cost also removes the residual length-dependent timing that a
// plaintext compare cannot.
func (s *Store) authenticate(username, password string) ([]*Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.users[username]

	stored := dummyPassword
	if ok {
		stored = acc.password
	}
	match := subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
	if !ok || !match {
		return nil, false
	}

	snapshot := make([]*Message, len(acc.messages))
	copy(snapshot, acc.messages)
	return snapshot, true
}

// expunge removes the given messages (by pointer identity) from the user's
// maildrop and returns how many were removed.
func (s *Store) expunge(username string, remove map[*Message]bool) int {
	if len(remove) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.users[username]
	if !ok {
		return 0
	}
	kept := acc.messages[:0:0]
	removed := 0
	for _, m := range acc.messages {
		if remove[m] {
			removed++
			continue
		}
		kept = append(kept, m)
	}
	acc.messages = kept
	return removed
}

// session is a per-connection POP3 session over an in-memory maildrop.
type session struct {
	store    *Store
	username string
	msgs     []*Message   // snapshot taken at login (1-based index = i+1)
	deleted  map[int]bool // marked-for-deletion message numbers
}

var (
	_ pop3server.Session     = (*session)(nil)
	_ pop3server.SessionSASL = (*session)(nil)
)

func (s *session) Close() error { return nil }

func (s *session) Login(_ context.Context, username, password string) error {
	msgs, ok := s.store.authenticate(username, password)
	if !ok {
		return &pop3server.Error{Code: "AUTH", Message: "authentication failed"}
	}
	s.username = username
	s.msgs = msgs
	return nil
}

func (s *session) AuthenticateMechanisms() []string { return []string{"PLAIN"} }

func (s *session) AuthenticatePlain(ctx context.Context, _identity, username, password string) error {
	return s.Login(ctx, username, password)
}

// msgAt returns the stored message for a 1-based number, or an error if the
// number is out of range or the message is marked deleted.
func (s *session) msgAt(msg int) (*Message, error) {
	if msg < 1 || msg > len(s.msgs) {
		return nil, &pop3server.Error{Message: "no such message"}
	}
	if s.deleted[msg] {
		return nil, &pop3server.Error{Message: "message is deleted"}
	}
	return s.msgs[msg-1], nil
}

func (s *session) Stat(_ context.Context) (count int, size int64, err error) {
	for i, m := range s.msgs {
		if s.deleted[i+1] {
			continue
		}
		count++
		size += int64(len(m.Data))
	}
	return count, size, nil
}

func (s *session) List(_ context.Context, msg int) ([]pop3.MessageInfo, error) {
	if msg > 0 {
		m, err := s.msgAt(msg)
		if err != nil {
			return nil, err
		}
		return []pop3.MessageInfo{{Num: msg, Size: int64(len(m.Data))}}, nil
	}
	var items []pop3.MessageInfo
	for i, m := range s.msgs {
		if s.deleted[i+1] {
			continue
		}
		items = append(items, pop3.MessageInfo{Num: i + 1, Size: int64(len(m.Data))})
	}
	return items, nil
}

func (s *session) Uidl(_ context.Context, msg int) ([]pop3.MessageUidl, error) {
	if msg > 0 {
		m, err := s.msgAt(msg)
		if err != nil {
			return nil, err
		}
		return []pop3.MessageUidl{{Num: msg, UniqueID: m.UID}}, nil
	}
	var items []pop3.MessageUidl
	for i, m := range s.msgs {
		if s.deleted[i+1] {
			continue
		}
		items = append(items, pop3.MessageUidl{Num: i + 1, UniqueID: m.UID})
	}
	return items, nil
}

func (s *session) Retr(_ context.Context, msg int) (io.ReadCloser, error) {
	m, err := s.msgAt(msg)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(m.Data)), nil
}

func (s *session) Top(_ context.Context, msg, lines int) (io.ReadCloser, error) {
	m, err := s.msgAt(msg)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(topBytes(m.Data, lines))), nil
}

func (s *session) Dele(_ context.Context, msg int) error {
	if msg < 1 || msg > len(s.msgs) {
		return &pop3server.Error{Message: "no such message"}
	}
	if s.deleted[msg] {
		return &pop3server.Error{Message: "message already deleted"}
	}
	s.deleted[msg] = true
	return nil
}

func (s *session) Rset(_ context.Context) error {
	s.deleted = make(map[int]bool)
	return nil
}

func (s *session) Noop(_ context.Context) error { return nil }

func (s *session) Quit(_ context.Context) (int, error) {
	if len(s.deleted) == 0 {
		return 0, nil
	}
	remove := make(map[*Message]bool, len(s.deleted))
	for num := range s.deleted {
		if num >= 1 && num <= len(s.msgs) {
			remove[s.msgs[num-1]] = true
		}
	}
	return s.store.expunge(s.username, remove), nil
}

// topBytes returns the message headers, the blank separator line, and up to
// n lines of the body. Lines are split on LF; CRLF is preserved.
func topBytes(data []byte, n int) []byte {
	// Locate the end of the header block (first blank line).
	sep := bytes.Index(data, []byte("\r\n\r\n"))
	sepLen := 4
	if sep < 0 {
		if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
			sep, sepLen = i, 2
		}
	}
	if sep < 0 {
		// No body separator: return everything (headers only).
		return append([]byte(nil), data...)
	}

	var out bytes.Buffer
	out.Write(data[:sep+sepLen]) // headers + blank line

	body := data[sep+sepLen:]
	if n <= 0 {
		return out.Bytes()
	}
	count := 0
	for len(body) > 0 && count < n {
		idx := bytes.IndexByte(body, '\n')
		if idx < 0 {
			out.Write(body)
			break
		}
		out.Write(body[:idx+1])
		body = body[idx+1:]
		count++
	}
	return out.Bytes()
}
