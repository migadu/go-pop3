package pop3server

import (
	"errors"
	"testing"
)

// failAfterWriter fails on its failOn-th Write call (1-based), succeeding
// before that.
type failAfterWriter struct {
	failOn int
	calls  int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls >= w.failOn {
		return 0, errors.New("boom")
	}
	return len(p), nil
}

// On a downstream error, Write must report the number of *input* bytes it
// fully processed (n < len(p) with a non-nil error), never len(p).
func TestDotStuffWriter_WriteErrorCount(t *testing.T) {
	// "ABCD": four plain bytes, one underlying write each. Fail on the 3rd
	// write (processing 'C'), so bytes 'A' and 'B' are fully consumed.
	w := &failAfterWriter{failOn: 3}
	d := newDotStuffWriter(w)
	n, err := d.Write([]byte("ABCD"))
	if err == nil {
		t.Fatal("expected error")
	}
	if n != 2 {
		t.Fatalf("consumed count: got %d, want 2", n)
	}
}

func TestDotStuffWriter_WriteErrorMidByte(t *testing.T) {
	// A leading '\n' expands to two writes ('\r' then '\n'). Failing on the
	// second write means byte 0 was not fully emitted, so n must be 0.
	w := &failAfterWriter{failOn: 2}
	d := newDotStuffWriter(w)
	n, err := d.Write([]byte("\nrest"))
	if err == nil {
		t.Fatal("expected error")
	}
	if n != 0 {
		t.Fatalf("consumed count for partially-written byte: got %d, want 0", n)
	}
}
