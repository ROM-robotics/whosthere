package probe

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// QueryNetBIOS sends a NetBIOS Node Status (NBSTAT) query to discover the
// NetBIOS name of the host at the given IP. Returns empty string on failure.
func QueryNetBIOS(ip string, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:137", ip)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	query := buildNBSTATQuery()
	if _, err := conn.Write(query); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	return parseNBSTATResponse(buf[:n])
}

// buildNBSTATQuery constructs a NetBIOS Node Status Request packet for the
// wildcard name "*" which returns all registered names on the target host.
func buildNBSTATQuery() []byte {
	packet := make([]byte, 50)

	// Transaction ID
	packet[0] = 0x00
	packet[1] = 0x01

	// Flags: 0x0000 (standard query)
	// Questions: 1
	packet[4] = 0x00
	packet[5] = 0x01

	// Query name: encoded "*" (wildcard NBSTAT query)
	// Length of first-level encoded name: 32 (0x20)
	packet[12] = 0x20

	// NetBIOS name encoding: each byte of the 16-char padded name is split
	// into two nibbles, each added to 'A' (0x41).
	// '*' = 0x2A → nibbles 2, A → 'C' (0x43), 'K' (0x4B)
	packet[13] = 0x43 // 'C'
	packet[14] = 0x4B // 'K'
	// ' ' = 0x20 → nibbles 2, 0 → 'C' (0x43), 'A' (0x41)
	for i := 0; i < 15; i++ {
		packet[15+i*2] = 0x43   // 'C'
		packet[15+i*2+1] = 0x41 // 'A'
	}

	// End of name
	packet[45] = 0x00

	// Type: NBSTAT (0x0021)
	packet[46] = 0x00
	packet[47] = 0x21

	// Class: IN (0x0001)
	packet[48] = 0x00
	packet[49] = 0x01

	return packet
}

// parseNBSTATResponse extracts the first unique NetBIOS name from an NBSTAT response.
func parseNBSTATResponse(data []byte) string {
	if len(data) < 57 {
		return ""
	}

	// Skip header (12 bytes), then walk through the query name
	pos := 12
	for pos < len(data) && data[pos] != 0x00 {
		labelLen := int(data[pos])
		pos += labelLen + 1
	}
	pos++    // skip name terminator (0x00)
	pos += 4 // skip query Type (2) + Class (2)

	if pos >= len(data) {
		return ""
	}

	// Answer name — may be a compressed pointer (0xC0xx) or a full label sequence
	if data[pos]&0xC0 == 0xC0 {
		pos += 2
	} else {
		for pos < len(data) && data[pos] != 0x00 {
			labelLen := int(data[pos])
			pos += labelLen + 1
		}
		pos++
	}

	// Skip Type (2) + Class (2) + TTL (4) + Data Length (2) = 10 bytes
	pos += 10
	if pos >= len(data) {
		return ""
	}

	// Number of name entries
	numNames := int(data[pos])
	pos++
	if numNames == 0 || pos+18 > len(data) {
		return ""
	}

	// Each entry: 15-byte name + 1-byte suffix + 2-byte flags
	for i := 0; i < numNames && pos+18 <= len(data); i++ {
		name := strings.TrimRight(string(data[pos:pos+15]), " \x00")
		suffix := data[pos+15]
		flags := uint16(data[pos+16])<<8 | uint16(data[pos+17])
		isGroup := flags&0x8000 != 0
		pos += 18

		// Return the first unique (non-group) workstation name (suffix 0x00)
		if suffix == 0x00 && !isGroup && name != "" {
			return name
		}
	}

	return ""
}
