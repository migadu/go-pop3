package pop3server

import (
	"bytes"
	"testing"
)

func TestDotStuffWriter_BasicMessage(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	w.Write([]byte("Subject: test\r\n\r\nHello world\r\n"))
	w.Close()

	want := "Subject: test\r\n\r\nHello world\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_DotAtLineStart(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	w.Write([]byte("line1\r\n.line2\r\n..line3\r\n"))
	w.Close()

	// Lines starting with '.' get an extra '.' prepended.
	want := "line1\r\n..line2\r\n...line3\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_BareLF(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	// Bare LF should be normalised to CRLF.
	w.Write([]byte("line1\nline2\n"))
	w.Close()

	want := "line1\r\nline2\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_BareLF_DotStuff(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	// Bare LF with a dot at the start of the next line.
	w.Write([]byte("line1\n.line2\n"))
	w.Close()

	want := "line1\r\n..line2\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_DotOnlyLine(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	// A lone "." on a line must be stuffed to ".." so the client doesn't
	// interpret it as the end-of-message terminator.
	w.Write([]byte("before\r\n.\r\nafter\r\n"))
	w.Close()

	want := "before\r\n..\r\nafter\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_EmptyBody(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)
	w.Close()

	// Even with no data, we need the terminating dot.
	want := ".\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_NoTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	// Body without trailing CRLF — Close should add one before the dot.
	w.Write([]byte("no trailing newline"))
	w.Close()

	want := "no trailing newline\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_IncrementalWrites(t *testing.T) {
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)

	// Write in small chunks to test state tracking across calls.
	w.Write([]byte("ab"))
	w.Write([]byte("c\r\n"))
	w.Write([]byte("."))
	w.Write([]byte("def\r\n"))
	w.Close()

	want := "abc\r\n..def\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_TrailingBareCR(t *testing.T) {
	// A body ending in a bare CR (no following LF) must normalise to a single
	// CRLF before the terminator, not "\r\r\n" with a stray CR.
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)
	w.Write([]byte("hello\r"))
	w.Close()

	want := "hello\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDotStuffWriter_TrailingBareCR_SplitWrites(t *testing.T) {
	// The bare CR arriving as the final byte of its own Write call must be
	// completed correctly at Close (state carries across Write boundaries).
	var buf bytes.Buffer
	w := newDotStuffWriter(&buf)
	w.Write([]byte("line"))
	w.Write([]byte("\r"))
	w.Close()

	want := "line\r\n.\r\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecodeSASLPlain(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		wantId   string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name:     "standard PLAIN",
			encoded:  "AGFsaWNlAHNlY3JldA==", // \x00alice\x00secret
			wantId:   "",
			wantUser: "alice",
			wantPass: "secret",
		},
		{
			name:     "with identity",
			encoded:  "Ym9iAGFsaWNlAHNlY3JldA==", // bob\x00alice\x00secret
			wantId:   "bob",
			wantUser: "alice",
			wantPass: "secret",
		},
		{
			name:    "invalid base64",
			encoded: "not-valid-base64!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, user, pass, err := decodeSASLPlain(tt.encoded)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tt.wantId || user != tt.wantUser || pass != tt.wantPass {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)",
					id, user, pass, tt.wantId, tt.wantUser, tt.wantPass)
			}
		})
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"1", 1, false},
		{"42", 42, false},
		{"999", 999, false},
		{"abc", 0, true},
		{"1a", 0, true},
		{"-1", 0, true},
	}

	for _, tt := range tests {
		got, err := parseInt(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("parseInt(%q): expected error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parseInt(%q): unexpected error: %v", tt.input, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("parseInt(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestSplitNull(t *testing.T) {
	tests := []struct {
		input []byte
		want  []string
	}{
		{[]byte("\x00alice\x00secret"), []string{"", "alice", "secret"}},
		{[]byte("bob\x00alice\x00secret"), []string{"bob", "alice", "secret"}},
		{[]byte("single"), []string{"single"}},
		{[]byte(""), []string{""}},
	}

	for _, tt := range tests {
		got := splitNull(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitNull(%q): got %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitNull(%q)[%d]: got %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}
