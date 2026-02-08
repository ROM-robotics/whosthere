//go:build darwin

package probe

import (
	"golang.org/x/sys/unix"
)

// readTTLFromSocket reads the IP_TTL socket option from a connected TCP socket.
func readTTLFromSocket(fd uintptr) int {
	ttl, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	if err != nil {
		return -1
	}
	return ttl
}
