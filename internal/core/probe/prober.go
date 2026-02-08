// Package probe provides network probing utilities for deep device inspection.
// It includes TCP ping, reverse DNS, banner grabbing, HTTP info, NetBIOS name
// queries, Wake-on-LAN, and device-type fingerprinting.
package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Result holds the aggregated results of all probes run against a device.
type Result struct {
	Latency     time.Duration
	ReverseDNS  string
	Banners     map[int]string // port -> service banner text
	HTTPTitle   string
	HTTPServer  string
	DeviceType  string
	NetBIOSName string
}

// Prober orchestrates various network probes against discovered devices.
type Prober struct {
	timeout time.Duration
}

// New creates a new Prober with the given per-probe timeout.
func New(timeout time.Duration) *Prober {
	return &Prober{timeout: timeout}
}

// RunAll executes all available probes against the given device IP and returns
// aggregated results. openPorts should contain known open TCP ports (from a
// prior port scan) so banners can be grabbed.
func (p *Prober) RunAll(ctx context.Context, ip, mac, manufacturer string, openPorts []int, extraData map[string]string) *Result {
	result := &Result{
		Banners: make(map[int]string),
	}
	log := zap.L().Named("probe")

	// 1. Reverse DNS
	log.Debug("reverse DNS lookup", zap.String("ip", ip))
	result.ReverseDNS = ReverseDNS(ip)

	// 2. TCP Ping
	log.Debug("TCP ping", zap.String("ip", ip))
	result.Latency = TCPPing(ctx, ip, openPorts, p.timeout)

	// 3. NetBIOS name query
	log.Debug("NetBIOS query", zap.String("ip", ip))
	result.NetBIOSName = QueryNetBIOS(ip, p.timeout)

	// 4. Banner grabbing on open ports
	if len(openPorts) > 0 {
		// Generic service banners (SSH, FTP, SMTP, etc.)
		for _, port := range openPorts {
			select {
			case <-ctx.Done():
				break
			default:
			}
			if isHTTPPort(port) {
				continue // handled separately below
			}
			log.Debug("grabbing banner", zap.String("ip", ip), zap.Int("port", port))
			if banner := GrabBanner(ctx, ip, port, p.timeout); banner != "" {
				result.Banners[port] = banner
			}
		}
		// HTTP-specific probing
		for _, port := range openPorts {
			select {
			case <-ctx.Done():
				break
			default:
			}
			if !isHTTPPort(port) {
				continue
			}
			log.Debug("fetching HTTP info", zap.String("ip", ip), zap.Int("port", port))
			title, server := FetchHTTPInfo(ctx, ip, port, p.timeout)
			if title != "" && result.HTTPTitle == "" {
				result.HTTPTitle = title
			}
			if server != "" && result.HTTPServer == "" {
				result.HTTPServer = server
			}
			// Store a composite banner for the port
			var parts []string
			if server != "" {
				parts = append(parts, server)
			}
			if title != "" {
				parts = append(parts, fmt.Sprintf("\"%s\"", title))
			}
			if len(parts) > 0 {
				result.Banners[port] = strings.Join(parts, " | ")
			}
		}
	}

	// 5. Device fingerprinting
	log.Debug("fingerprinting device", zap.String("ip", ip))
	result.DeviceType = Fingerprint(mac, manufacturer, openPorts, result.Banners, result.NetBIOSName, result.HTTPServer, extraData)

	return result
}

func isHTTPPort(port int) bool {
	return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 9090
}

// ReverseDNS performs a reverse DNS lookup (PTR record) for the given IP address.
func ReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// TCPPing measures round-trip latency by timing a TCP handshake to a known
// open port. It tries known ports first, then falls back to common ports.
func TCPPing(ctx context.Context, ip string, knownPorts []int, timeout time.Duration) time.Duration {
	ports := make([]int, 0, len(knownPorts)+4)
	ports = append(ports, knownPorts...)
	// Add common fallbacks if not already included
	for _, p := range []int{80, 443, 22, 135} {
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
			return 0
		default:
		}
		addr := fmt.Sprintf("%s:%d", ip, port)
		start := time.Now()
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		elapsed := time.Since(start)
		if err == nil {
			_ = conn.Close()
			return elapsed
		}
	}
	return 0
}
