package discovery

import (
	"fmt"
	"net"

	"go.uber.org/zap"
)

// InterfaceInfo holds the essential network interface information for scanning
type InterfaceInfo struct {
	Interface *net.Interface // Network interface
	IPv4Addr  *net.IP        // IPv4 host address used by the interface
	IPv4Net   *net.IPNet     // Subnet (e.g., 192.168.1.0/24)
}

// NewInterfaceInfo creates InterfaceInfo from a net.Interface
// It returns an error if the interface has no IPv4 address.
// This makes sure that every scanner has the necessary information to perform network scans.
// And makes interface handling consistent and swappable.
func NewInterfaceInfo(interfaceName string) (*InterfaceInfo, error) {
	iface, err := getNetworkInterface(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("get network interface %s: %w", interfaceName, err)
	}
	info := &InterfaceInfo{Interface: iface}

	addresses, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get addresses for %s: %w", iface.Name, err)
	}

	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			info.IPv4Addr = &ipnet.IP
			info.IPv4Net = ipnet
			break
		}
	}

	if info.IPv4Addr == nil {
		return nil, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
	}

	return info, nil
}

// getNetworkInterface returns the network interface by name.
// If interfaceName is empty, it attempts to return the OS default network interface.
func getNetworkInterface(interfaceName string) (*net.Interface, error) {
	var iface *net.Interface
	var err error
	if interfaceName != "" {
		if iface, err = net.InterfaceByName(interfaceName); err != nil {
			return nil, err
		}
		zap.L().Info("using specified network interface", zap.String("interface", interfaceName))
		return iface, nil
	}

	if iface, err = getDefaultInterface(); err != nil {
		zap.L().Info("failed to get default network interface", zap.Error(err))
		return nil, err
	}

	zap.L().Info("using default network interface", zap.String("interface", iface.Name))
	return iface, nil
}

// isLANSuitable returns true if the interface is suitable for LAN discovery.
// It filters out loopback, down, point-to-point (VPN/TUN), and interfaces
// without a usable IPv4 subnet (e.g. /32).
func isLANSuitable(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	// Point-to-point interfaces (VPN tunnels like outline-tun0, wg0, etc.)
	// are not suitable for LAN discovery because they don't support
	// broadcast/multicast needed by mDNS, SSDP, and ARP scanning.
	if iface.Flags&net.FlagPointToPoint != 0 {
		return false
	}
	// Must have broadcast capability for LAN protocols
	if iface.Flags&net.FlagBroadcast == 0 {
		return false
	}
	// Must have at least one IPv4 address with a subnet larger than /31
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones <= 30 {
			return true
		}
	}
	return false
}

// InterfaceEntry holds information about a network interface for display in the UI.
type InterfaceEntry struct {
	Name   string
	IPv4   string
	Subnet string
	MAC    string
	Flags  string
	IsVPN  bool
}

// ListAllInterfaces returns all non-loopback, up interfaces with IPv4 addresses,
// marking VPN/TUN interfaces so the UI can display them distinctly.
func ListAllInterfaces() []InterfaceEntry {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []InterfaceEntry
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			isVPN := iface.Flags&net.FlagPointToPoint != 0 || iface.Flags&net.FlagBroadcast == 0
			entry := InterfaceEntry{
				Name:   iface.Name,
				IPv4:   ipnet.IP.String(),
				Subnet: ipnet.String(),
				MAC:    iface.HardwareAddr.String(),
				IsVPN:  isVPN,
			}
			// Build flags description
			var flags []string
			if iface.Flags&net.FlagBroadcast != 0 {
				flags = append(flags, "broadcast")
			}
			if iface.Flags&net.FlagPointToPoint != 0 {
				flags = append(flags, "point-to-point")
			}
			if iface.Flags&net.FlagMulticast != 0 {
				flags = append(flags, "multicast")
			}
			if len(flags) > 0 {
				entry.Flags = fmt.Sprintf("[%s]", joinStrings(flags, ", "))
			}
			result = append(result, entry)
			break // one entry per interface
		}
	}
	return result
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// getDefaultInterface attempts to return the OS default network interface.
// It prefers LAN-suitable interfaces over VPN/tunnel interfaces.
func getDefaultInterface() (*net.Interface, error) {
	// First try UDP-based detection
	if iface, err := getInterfaceNameByUDP(); err == nil {
		// Verify the detected interface is LAN-suitable
		if isLANSuitable(*iface) {
			return iface, nil
		}
		zap.L().Warn("UDP-detected interface is not LAN-suitable (likely VPN)",
			zap.String("interface", iface.Name),
			zap.String("flags", iface.Flags.String()),
		)
	}

	// Fallback: find the best LAN-suitable interface
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Prefer broadcast-capable, non-VPN interfaces
	for _, iface := range interfaces {
		if isLANSuitable(iface) {
			zap.L().Info("selected LAN-suitable interface (VPN fallback)",
				zap.String("interface", iface.Name))
			return &iface, nil
		}
	}

	// Last resort: any non-loopback, up interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			zap.L().Warn("no LAN-suitable interface found, using first available",
				zap.String("interface", iface.Name))
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no network interface found")
}

// getInterfaceNameByUDP tries to determine the default network interface
// by creating a UDP connection to a public IP and checking the local address used.
func getInterfaceNameByUDP() (*net.Interface, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.Equal(localAddr.IP) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("interface not found for IP %s", localAddr.IP)
}

// GetInterfaceIP returns the first IPv4 address of the interface.
// Returns an error if no IPv4 address is found.
func GetInterfaceIP(iface *net.Interface) (net.IP, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addresses {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}
