package arp

import (
	"net"

	"go.uber.org/zap"
)

// generateSubnetIPs generates a list of IPs in the given subnet,
// Skipping the specified IP (usually the interface's own IP).
// It includes the network address and broadcast address.
// It limits the scan to a /16 equivalent if the subnet is larger.
// In that case it will only scan the first 65534 IPs of that subnet.
func generateSubnetIPs(subnet *net.IPNet, skipIP net.IP) []net.IP {
	// If users request it, we could potentially add an option to override the /16 limit via configuration?
	var ips []net.IP
	network := subnet.IP.To4()
	if network == nil {
		return ips
	}

	ones, _ := subnet.Mask.Size()
	if ones < 16 {
		zap.L().Warn("large subnet detected, limiting ARP scan to /16 equivalent", zap.Int("prefix", ones), zap.String("subnet", subnet.String()))
	}

	networkIP := subnet.IP.Mask(subnet.Mask)
	broadcastIP := make(net.IP, len(networkIP))
	copy(broadcastIP, networkIP)

	effectiveMask := subnet.Mask
	if ones < 16 {
		effectiveMask = net.CIDRMask(16, 32)
	}
	for i := range network {
		// sets broadcast IP to a /16 equivalent if subnet is larger
		broadcastIP[i] |= ^effectiveMask[i]
	}

	currentIP := make(net.IP, len(networkIP))
	copy(currentIP, networkIP)

	for {
		if !currentIP.Equal(skipIP) {
			ipCopy := make(net.IP, len(currentIP))
			copy(ipCopy, currentIP)
			ips = append(ips, ipCopy)
		}
		if currentIP.Equal(broadcastIP) {
			break
		}
		currentIP = incrementIP(currentIP)
	}

	return ips
}

// incrementIP increments the IP address by 1
func incrementIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}
