package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// OS name constants for detected operating systems.
const (
	OSWindows = "Windows"
	OSLinux   = "Linux"
	OSMacOS   = "macOS"
	OSFreeBSD = "FreeBSD"
	OSAndroid = "Android"
	OSIOS     = "iOS"
	OSUnknown = ""
)

// DetectOS attempts to determine the operating system of a remote host by
// combining multiple heuristic signals:
//  1. SSH banner analysis (e.g. "OpenSSH_8.9p1 Ubuntu")
//  2. HTTP Server header analysis (e.g. "Microsoft-IIS")
//  3. Service banners from other ports
//  4. mDNS/SSDP extra data keywords
//  5. NetBIOS name presence (strong Windows signal)
//  6. TCP TTL-based fingerprinting
//  7. Open port heuristics
func DetectOS(ctx context.Context, ip string, openPorts []int, banners map[int]string, httpServer, netbiosName string, extraData map[string]string, timeout time.Duration) string {
	// 1. SSH banner — most reliable text signal
	if os := osFromSSHBanner(banners); os != "" {
		return os
	}

	// 2. HTTP Server header
	if os := osFromHTTPServer(httpServer); os != "" {
		return os
	}

	// 3. Other service banners
	if os := osFromBanners(banners); os != "" {
		return os
	}

	// 4. mDNS / SSDP extra data
	if os := osFromExtraData(extraData); os != "" {
		return os
	}

	// 5. NetBIOS name present → likely Windows
	if netbiosName != "" {
		return OSWindows
	}

	// 6. TCP TTL fingerprint
	if os := osFromTTL(ctx, ip, openPorts, timeout); os != "" {
		return os
	}

	// 7. Port-based heuristics
	if os := osFromPorts(openPorts); os != "" {
		return os
	}

	return OSUnknown
}

// osFromSSHBanner inspects the SSH banner on port 22 for OS hints.
func osFromSSHBanner(banners map[int]string) string {
	banner, ok := banners[22]
	if !ok || banner == "" {
		return ""
	}
	b := strings.ToLower(banner)

	// Ubuntu, Debian, Fedora, CentOS, etc. → Linux
	linuxHints := []string{"ubuntu", "debian", "fedora", "centos", "rhel",
		"arch", "gentoo", "opensuse", "suse", "alpine", "kali", "mint",
		"manjaro", "raspbian", "raspberry", "armbian"}
	for _, hint := range linuxHints {
		if strings.Contains(b, hint) {
			return OSLinux
		}
	}

	// FreeBSD
	if strings.Contains(b, "freebsd") {
		return OSFreeBSD
	}

	// Generic Linux signal: OpenSSH on non-Windows usually means Linux/Unix
	// Windows OpenSSH banners often say "Microsoft" or "Windows"
	if strings.Contains(b, "microsoft") || strings.Contains(b, "windows") {
		return OSWindows
	}

	// If it's OpenSSH but no OS-specific hint, it's likely Linux
	if strings.Contains(b, "openssh") {
		return OSLinux
	}

	return ""
}

// osFromHTTPServer checks the HTTP Server header for OS fingerprints.
func osFromHTTPServer(server string) string {
	if server == "" {
		return ""
	}
	s := strings.ToLower(server)

	if strings.Contains(s, "microsoft") || strings.Contains(s, "iis") {
		return OSWindows
	}
	if strings.Contains(s, "ubuntu") || strings.Contains(s, "debian") ||
		strings.Contains(s, "centos") || strings.Contains(s, "fedora") ||
		strings.Contains(s, "red hat") {
		return OSLinux
	}
	if strings.Contains(s, "darwin") || strings.Contains(s, "macos") {
		return OSMacOS
	}
	if strings.Contains(s, "freebsd") {
		return OSFreeBSD
	}
	return ""
}

// osFromBanners scans all service banners for OS keywords.
func osFromBanners(banners map[int]string) string {
	for port, banner := range banners {
		if port == 22 {
			continue // already handled by osFromSSHBanner
		}
		b := strings.ToLower(banner)

		if strings.Contains(b, "windows") || strings.Contains(b, "microsoft") || strings.Contains(b, "win32") || strings.Contains(b, "win64") {
			return OSWindows
		}
		if strings.Contains(b, "ubuntu") || strings.Contains(b, "debian") ||
			strings.Contains(b, "centos") || strings.Contains(b, "fedora") ||
			strings.Contains(b, "linux") {
			return OSLinux
		}
		if strings.Contains(b, "darwin") || strings.Contains(b, "macos") || strings.Contains(b, "mac os") {
			return OSMacOS
		}
		if strings.Contains(b, "freebsd") {
			return OSFreeBSD
		}
	}
	return ""
}

// osFromExtraData inspects mDNS/SSDP metadata for OS signals.
func osFromExtraData(extra map[string]string) string {
	if len(extra) == 0 {
		return ""
	}
	combined := strings.ToLower(flattenMap(extra))

	// iOS devices (check before general Apple)
	if strings.Contains(combined, "iphone") || strings.Contains(combined, "ipad") ||
		strings.Contains(combined, "ipod") {
		return OSIOS
	}

	// Apple ecosystem → macOS
	if strings.Contains(combined, "apple") || strings.Contains(combined, "airplay") ||
		strings.Contains(combined, "_companion-link") || strings.Contains(combined, "macos") ||
		strings.Contains(combined, "mac os") {
		return OSMacOS
	}

	// Android
	if strings.Contains(combined, "android") {
		return OSAndroid
	}

	// Windows
	if strings.Contains(combined, "windows") || strings.Contains(combined, "microsoft") {
		return OSWindows
	}

	// Linux
	if strings.Contains(combined, "linux") || strings.Contains(combined, "ubuntu") ||
		strings.Contains(combined, "debian") || strings.Contains(combined, "fedora") {
		return OSLinux
	}

	return ""
}

// osFromTTL performs a TCP connection to determine the initial TTL value
// which varies by OS:
//
//	Windows: 128, Linux/Android: 64, macOS/iOS: 64, FreeBSD: 64
//
// Since Linux and macOS both use 64, this is useful mainly for distinguishing
// Windows (128) from Unix-like systems.
func osFromTTL(ctx context.Context, ip string, knownPorts []int, timeout time.Duration) string {
	ports := make([]int, 0, len(knownPorts)+3)
	ports = append(ports, knownPorts...)
	for _, p := range []int{80, 443, 22} {
		found := false
		for _, kp := range ports {
			if kp == p {
				found = true
				break
			}
		}
		if !found {
			ports = append(ports, p)
		}
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return ""
		default:
		}
		ttl := getTTL(ip, port, timeout)
		if ttl <= 0 {
			continue
		}
		return classifyTTL(ttl)
	}
	return ""
}

// getTTL connects to the given addr via TCP and reads the TTL from the
// IP header of the SYN-ACK. Works on Linux via syscall control messages.
func getTTL(ip string, port int, timeout time.Duration) int {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: timeout}

	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return -1
	}
	defer func() { _ = conn.Close() }()

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return -1
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return -1
	}

	var ttl int
	err = raw.Control(func(fd uintptr) {
		ttl = readTTLFromSocket(fd)
	})
	if err != nil {
		return -1
	}
	return ttl
}

// classifyTTL maps a received TTL value to an OS guess.
// Initial TTL values decrease with each hop. We use ranges:
//
//	  1-64   → probably started at 64  → Linux/macOS/FreeBSD
//	 65-128  → probably started at 128 → Windows
//	129-255  → probably started at 255 → Solaris/rare
func classifyTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return OSLinux // could also be macOS/FreeBSD — refined by other heuristics
	case ttl <= 128:
		return OSWindows
	default:
		return OSLinux // rare: Solaris etc.
	}
}

// osFromPorts uses well-known port patterns as a last resort.
func osFromPorts(ports []int) string {
	portSet := make(map[int]bool, len(ports))
	for _, p := range ports {
		portSet[p] = true
	}

	// RDP (3389) + SMB (445) + WinRM (5985) → very likely Windows
	if portSet[3389] || (portSet[445] && portSet[5985]) {
		return OSWindows
	}
	// AFP (548) → macOS
	if portSet[548] {
		return OSMacOS
	}

	return ""
}
