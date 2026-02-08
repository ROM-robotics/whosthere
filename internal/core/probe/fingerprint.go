package probe

import (
	"strings"
)

// Device type constants for common classification categories.
const (
	TypeRouter      = "Router/Gateway"
	TypeSwitch      = "Network Switch"
	TypeAP          = "Access Point"
	TypePrinter     = "Printer"
	TypeNAS         = "NAS/Storage"
	TypeCamera      = "IP Camera"
	TypeSmartTV     = "Smart TV"
	TypePhone       = "Phone/Tablet"
	TypeDesktop     = "Desktop/Laptop"
	TypeServer      = "Server"
	TypeIoT         = "IoT Device"
	TypeSmartHome   = "Smart Home"
	TypeGameConsole = "Game Console"
	TypeUnknown     = "Unknown"
)

// Fingerprint attempts to classify a device based on available information:
// MAC/OUI manufacturer, open ports, service banners, NetBIOS name, HTTP
// server header, and mDNS/SSDP extra data.
func Fingerprint(mac, manufacturer string, openPorts []int, banners map[int]string, netbiosName, httpServer string, extraData map[string]string) string {
	mfr := strings.ToLower(manufacturer)
	srv := strings.ToLower(httpServer)

	allExtra := strings.ToLower(flattenMap(extraData))

	// 1. Manufacturer-based classification (most reliable)
	if t := fingerprintByManufacturer(mfr); t != "" {
		return t
	}

	// 2. Service/mDNS/SSDP data
	if t := fingerprintByServices(allExtra); t != "" {
		return t
	}

	// 3. Port & banner analysis
	if t := fingerprintByPorts(openPorts, banners, srv); t != "" {
		return t
	}

	return TypeUnknown
}

func fingerprintByManufacturer(mfr string) string {
	if mfr == "" {
		return ""
	}

	rules := []struct {
		keywords []string
		dtype    string
	}{
		{[]string{"apple", "samsung", "huawei", "xiaomi", "oppo", "vivo", "oneplus",
			"motorola", "nokia", "sony mobile", "google", "pixel"}, TypePhone},
		{[]string{"canon", "epson", "brother", "lexmark", "xerox", "ricoh",
			"kyocera", "konica"}, TypePrinter},
		{[]string{"cisco", "juniper", "arista", "ubiquiti", "mikrotik", "netgear",
			"tp-link", "d-link", "linksys", "zyxel", "zte"}, TypeRouter},
		{[]string{"synology", "qnap", "western digital", "buffalo", "seagate"}, TypeNAS},
		{[]string{"lg electronics", "tcl", "hisense", "vizio", "roku"}, TypeSmartTV},
		{[]string{"nintendo", "valve"}, TypeGameConsole},
		{[]string{"espressif", "tuya", "shelly", "sonoff", "wemo", "ring",
			"nest", "amazon", "echo"}, TypeSmartHome},
		{[]string{"dell", "lenovo", "hewlett", "hp inc", "acer", "intel",
			"realtek", "gigabyte", "msi", "asustek"}, TypeDesktop},
		{[]string{"hikvision", "dahua", "axis", "reolink", "amcrest", "wyze"}, TypeCamera},
	}

	for _, rule := range rules {
		for _, kw := range rule.keywords {
			if strings.Contains(mfr, kw) {
				return rule.dtype
			}
		}
	}
	return ""
}

func fingerprintByServices(extra string) string {
	if extra == "" {
		return ""
	}

	rules := []struct {
		keywords []string
		dtype    string
	}{
		{[]string{"printer", "_ipp.", "_pdl-"}, TypePrinter},
		{[]string{"chromecast", "googlecast", "smarttv", "roku", "airplay", "_raop."}, TypeSmartTV},
		{[]string{"camera", "ipcam"}, TypeCamera},
		{[]string{"_smb.", "_afp.", "timemachine"}, TypeNAS},
		{[]string{"homekit", "_hap."}, TypeSmartHome},
		{[]string{"playstation", "xbox", "nintendo"}, TypeGameConsole},
	}

	for _, rule := range rules {
		for _, kw := range rule.keywords {
			if strings.Contains(extra, kw) {
				return rule.dtype
			}
		}
	}
	return ""
}

func fingerprintByPorts(ports []int, banners map[int]string, httpServer string) string {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	// Printer ports
	if portSet[9100] || portSet[631] {
		return TypePrinter
	}

	// RTSP → camera
	if portSet[554] {
		return TypeCamera
	}

	// DNS/DHCP → router
	if portSet[53] || portSet[67] || portSet[68] {
		return TypeRouter
	}

	// SMB + web UI → NAS
	if portSet[139] && portSet[445] && (portSet[80] || portSet[443]) {
		return TypeNAS
	}

	// Server-like: SSH + HTTP + database
	if portSet[22] && (portSet[80] || portSet[443]) {
		if portSet[3306] || portSet[5432] || portSet[27017] || portSet[9200] || portSet[6379] {
			return TypeServer
		}
	}

	// HTTP server header hints
	if httpServer != "" {
		if strings.Contains(httpServer, "printer") || strings.Contains(httpServer, "cups") {
			return TypePrinter
		}
	}

	// SSH banner → desktop
	allBanners := strings.ToLower(flattenBanners(banners))
	if strings.Contains(allBanners, "ssh") {
		return TypeDesktop
	}

	return ""
}

func flattenMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, k+" "+v)
	}
	return strings.Join(parts, " ")
}

func flattenBanners(m map[int]string) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for _, v := range m {
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}
