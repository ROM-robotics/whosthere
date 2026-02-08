package probe

import (
	"fmt"
	"net"
)

// SendWoL sends a Wake-on-LAN magic packet for the given MAC address.
// broadcastAddr should be the subnet broadcast address (e.g. "192.168.1.255").
func SendWoL(macStr string, broadcastAddr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", macStr, err)
	}
	if len(mac) != 6 {
		return fmt.Errorf("MAC address must be 6 bytes, got %d", len(mac))
	}

	// Build magic packet: 6 bytes of 0xFF followed by 16 repetitions of the MAC.
	var packet [102]byte
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], mac)
	}

	addr := fmt.Sprintf("%s:%d", broadcastAddr, 9)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("dial broadcast %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err = conn.Write(packet[:]); err != nil {
		return fmt.Errorf("send WoL packet: %w", err)
	}
	return nil
}

// BroadcastAddr computes the broadcast address from an IP network.
func BroadcastAddr(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipNet.Mask
	broadcast := make(net.IP, 4)
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}
