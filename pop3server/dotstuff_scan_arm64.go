//go:build arm64 && !purego && !pop3scalar

package pop3server

import "bytes"

// ordinaryPrefixVector returns a prefix that can be skipped before the scalar scan.
// The caller has already checked p[0]. Each vector checks both bare LFs and
// dots preceded by LF, using overlapping current/previous-byte loads. It
// leaves one validated byte for the scalar scan to see a boundary LF/dot pair.
// Every vector load stays within p; no padding or alignment is required.
//
//go:noescape
func ordinaryPrefixVector(p []byte) int

func ordinaryPrefix(p []byte) int {
	// Preserve the fast standard-library search for long, newline-free spans.
	if bytes.IndexByte(p, '\n') < 0 {
		return len(p)
	}
	return ordinaryPrefixVector(p)
}
