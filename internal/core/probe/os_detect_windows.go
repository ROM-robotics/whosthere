//go:build windows

package probe

// readTTLFromSocket is a stub for Windows; TTL fingerprinting is not
// supported through raw socket options on Windows.
func readTTLFromSocket(_ uintptr) int {
	return -1
}
