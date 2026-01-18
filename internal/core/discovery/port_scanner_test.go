package discovery

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// mockConn is a minimal implementation of net.Conn for testing.
type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockDialer is a mock implementation of Dialer for testing.
type mockDialer struct {
	openPorts map[string]bool
}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if m.openPorts[address] {
		return &mockConn{}, nil // simulate open
	}
	return nil, net.ErrClosed // simulate closed
}

func TestPortScanner_Stream(t *testing.T) {
	mock := &mockDialer{
		openPorts: map[string]bool{
			"127.0.0.1:80":  true,
			"127.0.0.1:443": true,
		},
	}
	ps := &PortScanner{
		workers: 2,
		dialer:  mock,
	}

	ports := []int{22, 80, 443, 8080}
	var openPorts []int
	var mu sync.Mutex
	err := ps.Stream(context.Background(), "127.0.0.1", ports, 100*time.Millisecond, func(port int) {
		mu.Lock()
		openPorts = append(openPorts, port)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}

	expected := []int{80, 443}
	if len(openPorts) != len(expected) {
		t.Errorf("expected %d open ports, got %d", len(expected), len(openPorts))
	}
	for _, p := range expected {
		found := false
		for _, op := range openPorts {
			if op == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected port %d to be open", p)
		}
	}
}

func TestPortScanner_Stream_EmptyPorts(t *testing.T) {
	ps := NewPortScanner(1)
	var openPorts []int
	var mu sync.Mutex
	err := ps.Stream(context.Background(), "127.0.0.1", []int{}, 100*time.Millisecond, func(port int) {
		mu.Lock()
		openPorts = append(openPorts, port)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Stream failed: %v", err)
	}
	if len(openPorts) != 0 {
		t.Errorf("expected no open ports, got %d", len(openPorts))
	}
}
