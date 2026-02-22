package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	// Test disabled rate limiter (requests = 0).
	l := New(0, time.Minute)
	if l.IsEnabled() {
		t.Error("IsEnabled() should return false when requests is 0 (disabled)")
	}

	// Test with limit of 2 requests per minute.
	l = New(2, time.Minute)
	if !l.IsEnabled() {
		t.Error("IsEnabled() should return true with positive requests")
	}

	// First two requests should be allowed.
	if !l.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !l.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}

	// Third request should be denied.
	if l.Allow("192.168.1.1") {
		t.Error("Third request should be denied")
	}

	// Different IP should still be allowed.
	if !l.Allow("192.168.1.2") {
		t.Error("Request from different IP should be allowed")
	}
}

func TestRateLimiter_Window(t *testing.T) {
	// Test with a very short window.
	l := New(1, 50*time.Millisecond)

	// First request allowed.
	if !l.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}

	// Second request denied.
	if l.Allow("192.168.1.1") {
		t.Error("Second request should be denied")
	}

	// Wait for window to pass.
	time.Sleep(100 * time.Millisecond)

	// Now request should be allowed again.
	if !l.Allow("192.168.1.1") {
		t.Error("Request after window should be allowed")
	}
}

func TestRateLimiter_Middleware(t *testing.T) {
	l := New(1, time.Minute)

	// Create a simple handler that returns 200.
	handler := l.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// First request should pass.
	req1 := httptest.NewRequest("GET", "/", nil)
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr1.Code)
	}

	// Second request should be rate limited.
	req2 := httptest.NewRequest("GET", "/", nil)
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", rr2.Code)
	}

	// Check Retry-After header.
	if rr2.Header().Get("Retry-After") == "" {
		t.Error("Expected Retry-After header")
	}
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

func TestRateLimiter_Cleanup(t *testing.T) {
	// Create limiter with short window.
	l := New(10, 100*time.Millisecond)

	// Add requests from multiple IPs.
	l.Allow("192.168.1.1")
	l.Allow("192.168.1.2")
	l.Allow("192.168.1.3")

	// Wait for window to expire.
	time.Sleep(150 * time.Millisecond)

	// Cleanup should remove old entries.
	l.Cleanup()

	// All IPs should be able to make requests again.
	if !l.Allow("192.168.1.1") {
		t.Error("Request from 192.168.1.1 should be allowed after cleanup")
	}
	if !l.Allow("192.168.1.2") {
		t.Error("Request from 192.168.1.2 should be allowed after cleanup")
	}
	if !l.Allow("192.168.1.3") {
		t.Error("Request from 192.168.1.3 should be allowed after cleanup")
	}
}
