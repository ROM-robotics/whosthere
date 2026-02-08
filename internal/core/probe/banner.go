package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>\s*([^<]+?)\s*</title>`)

// GrabBanner connects to the given TCP port and reads any initial service
// banner (SSH, FTP, SMTP, etc. send a greeting upon connection).
func GrabBanner(ctx context.Context, ip string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]))
}

// FetchHTTPInfo sends an HTTP GET request and extracts the Server header
// and HTML <title>. It skips TLS certificate verification.
func FetchHTTPInfo(ctx context.Context, ip string, port int, timeout time.Duration) (title, server string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "whosthere/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer func() { _ = resp.Body.Close() }()

	server = resp.Header.Get("Server")

	// Read limited body to find <title>
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err == nil && len(body) > 0 {
		if matches := titleRe.FindSubmatch(body); len(matches) > 1 {
			title = strings.TrimSpace(string(matches[1]))
			if len(title) > 80 {
				title = title[:77] + "..."
			}
		}
	}

	return title, server
}

// sanitizeBanner cleans a raw banner: keeps first line, strips control chars.
func sanitizeBanner(raw string) string {
	if idx := strings.IndexAny(raw, "\r\n"); idx >= 0 {
		raw = raw[:idx]
	}
	var clean strings.Builder
	for _, r := range raw {
		if r >= 32 && r < 127 {
			clean.WriteRune(r)
		}
	}
	result := strings.TrimSpace(clean.String())
	if len(result) > 120 {
		result = result[:117] + "..."
	}
	return result
}
