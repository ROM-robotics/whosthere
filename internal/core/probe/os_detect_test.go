package probe

import (
	"testing"
)

func TestOsFromSSHBanner_Ubuntu(t *testing.T) {
	banners := map[int]string{22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"}
	got := osFromSSHBanner(banners)
	if got != OSLinux {
		t.Errorf("expected %q, got %q", OSLinux, got)
	}
}

func TestOsFromSSHBanner_Windows(t *testing.T) {
	banners := map[int]string{22: "SSH-2.0-OpenSSH_for_Windows_8.1"}
	got := osFromSSHBanner(banners)
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromSSHBanner_GenericOpenSSH(t *testing.T) {
	banners := map[int]string{22: "SSH-2.0-OpenSSH_9.0"}
	got := osFromSSHBanner(banners)
	if got != OSLinux {
		t.Errorf("expected %q, got %q", OSLinux, got)
	}
}

func TestOsFromSSHBanner_Empty(t *testing.T) {
	banners := map[int]string{}
	got := osFromSSHBanner(banners)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestOsFromHTTPServer_IIS(t *testing.T) {
	got := osFromHTTPServer("Microsoft-IIS/10.0")
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromHTTPServer_Ubuntu(t *testing.T) {
	got := osFromHTTPServer("Apache/2.4.41 (Ubuntu)")
	if got != OSLinux {
		t.Errorf("expected %q, got %q", OSLinux, got)
	}
}

func TestOsFromHTTPServer_Empty(t *testing.T) {
	got := osFromHTTPServer("")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestOsFromHTTPServer_FreeBSD(t *testing.T) {
	got := osFromHTTPServer("nginx/1.24.0 (FreeBSD)")
	if got != OSFreeBSD {
		t.Errorf("expected %q, got %q", OSFreeBSD, got)
	}
}

func TestOsFromBanners_WindowsFTP(t *testing.T) {
	banners := map[int]string{21: "220 Microsoft FTP Service"}
	got := osFromBanners(banners)
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromBanners_Linux(t *testing.T) {
	banners := map[int]string{25: "220 mail.example.com ESMTP Postfix (Ubuntu)"}
	got := osFromBanners(banners)
	if got != OSLinux {
		t.Errorf("expected %q, got %q", OSLinux, got)
	}
}

func TestOsFromBanners_Port22Skipped(t *testing.T) {
	banners := map[int]string{22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"}
	got := osFromBanners(banners)
	if got != "" {
		t.Errorf("expected empty (port 22 skipped), got %q", got)
	}
}

func TestOsFromExtraData_Apple(t *testing.T) {
	extra := map[string]string{"mdns.service": "_airplay._tcp"}
	got := osFromExtraData(extra)
	if got != OSMacOS {
		t.Errorf("expected %q, got %q", OSMacOS, got)
	}
}

func TestOsFromExtraData_Android(t *testing.T) {
	extra := map[string]string{"ssdp.server": "Android/12 UPnP/1.0"}
	got := osFromExtraData(extra)
	if got != OSAndroid {
		t.Errorf("expected %q, got %q", OSAndroid, got)
	}
}

func TestOsFromExtraData_Windows(t *testing.T) {
	extra := map[string]string{"ssdp.server": "Microsoft-Windows/10.0"}
	got := osFromExtraData(extra)
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromExtraData_IOS(t *testing.T) {
	extra := map[string]string{"mdns.name": "iPhone-12._companion-link._tcp"}
	got := osFromExtraData(extra)
	if got != OSIOS {
		t.Errorf("expected %q, got %q", OSIOS, got)
	}
}

func TestOsFromExtraData_Empty(t *testing.T) {
	got := osFromExtraData(nil)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestClassifyTTL_Windows(t *testing.T) {
	tests := []struct {
		ttl  int
		want string
	}{
		{128, OSWindows},
		{120, OSWindows},
		{65, OSWindows},
	}
	for _, tc := range tests {
		got := classifyTTL(tc.ttl)
		if got != tc.want {
			t.Errorf("classifyTTL(%d) = %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestClassifyTTL_Linux(t *testing.T) {
	tests := []struct {
		ttl  int
		want string
	}{
		{64, OSLinux},
		{55, OSLinux},
		{1, OSLinux},
	}
	for _, tc := range tests {
		got := classifyTTL(tc.ttl)
		if got != tc.want {
			t.Errorf("classifyTTL(%d) = %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

func TestClassifyTTL_Zero(t *testing.T) {
	got := classifyTTL(0)
	if got != "" {
		t.Errorf("classifyTTL(0) = %q, want empty", got)
	}
}

func TestOsFromPorts_Windows(t *testing.T) {
	got := osFromPorts([]int{80, 135, 445, 3389})
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromPorts_WinRM(t *testing.T) {
	got := osFromPorts([]int{445, 5985})
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}

func TestOsFromPorts_MacOS(t *testing.T) {
	got := osFromPorts([]int{22, 548, 80})
	if got != OSMacOS {
		t.Errorf("expected %q, got %q", OSMacOS, got)
	}
}

func TestOsFromPorts_Unknown(t *testing.T) {
	got := osFromPorts([]int{80, 443})
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestDetectOS_SSHBannerPriority(t *testing.T) {
	banners := map[int]string{22: "SSH-2.0-OpenSSH_8.6p1 Ubuntu-4ubuntu0.5"}
	got := DetectOS(nil, "127.0.0.1", []int{22, 3389}, banners, "", "", nil, 0)
	if got != OSLinux {
		t.Errorf("expected %q, got %q", OSLinux, got)
	}
}

func TestDetectOS_NetBIOSFallback(t *testing.T) {
	got := DetectOS(nil, "127.0.0.1", nil, nil, "", "WORKSTATION", nil, 0)
	if got != OSWindows {
		t.Errorf("expected %q, got %q", OSWindows, got)
	}
}
