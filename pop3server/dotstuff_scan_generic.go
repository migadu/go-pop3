//go:build !arm64 || purego || pop3scalar

package pop3server

// Other architectures and purego builds use the existing scalar scanner.
func ordinaryPrefix(p []byte) int { return 0 }
