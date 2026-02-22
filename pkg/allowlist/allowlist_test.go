package allowlist

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowlist_New(t *testing.T) {
	// Test empty allowlist (allow all).
	a, err := New([]string{})
	if err != nil {
		t.Errorf("New() with empty list should not error: %v", err)
	}
	if a.IsEnabled() {
		t.Error("IsEnabled() should be false for empty allowlist")
	}

	// Test with valid IPs.
	a, err = New([]string{"192.168.1.1", "10.0.0.0/8"})
	if err != nil {
		t.Errorf("New() with valid IPs should not error: %v", err)
	}
	if !a.IsEnabled() {
		t.Error("IsEnabled() should be true for non-empty allowlist")
	}

	// Test with invalid input.
	_, err = New([]string{"invalid-ip"})
	if err == nil {
		t.Error("New() should error with invalid IP")
	}
}

func TestAllowlist_Allowed(t *testing.T) {
	a, err := New([]string{"192.168.1.0/24", "10.0.0.50"})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.100", true},
		{"192.168.1.255", true},
		{"10.0.0.50", true},
		{"192.168.2.1", false},
		{"10.0.0.51", false},
		{"172.16.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := a.Allowed(tt.ip)
			if got != tt.allowed {
				t.Errorf("Allowed(%q) = %v, want %v", tt.ip, got, tt.allowed)
			}
		})
	}
}

func TestAllowlist_AllowedEmpty(t *testing.T) {
	// Empty allowlist should allow all.
	a, _ := New([]string{})

	tests := []string{"192.168.1.1", "10.0.0.1", "0.0.0.0", "255.255.255.255"}
	for _, ip := range tests {
		if !a.Allowed(ip) {
			t.Errorf("Allowed(%q) should be true for empty allowlist", ip)
		}
	}
}

func TestAllowlist_Middleware(t *testing.T) {
	a, _ := New([]string{"192.168.1.0/24"})

	// Create a handler that returns 200.
	handler := a.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test allowed IP.
	t.Run("allowed IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}
	})

	// Test denied IP.
	t.Run("denied IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", rr.Code)
		}
	})
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For single",
			remoteAddr: "10.0.0.1:12345",
			forwarded:  "192.168.1.100",
			want:       "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For multiple",
			remoteAddr: "10.0.0.1:12345",
			forwarded:  "192.168.1.100, 10.0.0.2, 10.0.0.3",
			want:       "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}

			got := extractIP(req)
			if got != tt.want {
				t.Errorf("extractIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
