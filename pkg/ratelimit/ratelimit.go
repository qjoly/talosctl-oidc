// Package ratelimit provides rate limiting functionality for the HTTP server.
// It implements a per-IP sliding window rate limiter with configurable
// request limits and time windows.
package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter implements a sliding window rate limiter per IP address.
type Limiter struct {
	requests int           // Max requests allowed per window
	window   time.Duration // Time window for rate limiting
	clients  map[string]*client
	mu       sync.RWMutex
}

// client tracks request timestamps for a single IP.
type client struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// New creates a new rate limiter with the specified request limit and window.
// If requests is 0, rate limiting is disabled.
func New(requests int, window time.Duration) *Limiter {
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		requests: requests,
		window:   window,
		clients:  make(map[string]*client),
	}
}

// IsEnabled returns true if rate limiting is enabled.
func (l *Limiter) IsEnabled() bool {
	return l != nil && l.requests > 0
}

// Allow checks if a request from the given IP is allowed.
// It returns true if the request is within the rate limit.
func (l *Limiter) Allow(ip string) bool {
	if !l.IsEnabled() {
		return true
	}

	// Clean up old timestamps outside the window.
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	c, exists := l.clients[ip]
	if !exists {
		c = &client{}
		l.clients[ip] = c
	}
	l.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove timestamps outside the window.
	valid := c.timestamps[:0]
	for _, ts := range c.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	c.timestamps = valid

	// Check if we're over the limit.
	if len(c.timestamps) >= l.requests {
		return false
	}

	// Record this request.
	c.timestamps = append(c.timestamps, now)
	return true
}

// extractIP extracts the client IP from the request, handling X-Forwarded-For header.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for requests behind proxy).
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP if multiple are present.
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			return ip
		}
	}

	// Fall back to RemoteAddr.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// Middleware returns an HTTP middleware that applies rate limiting.
// If the limit is exceeded, it returns 429 Too Many Requests.
func (l *Limiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.IsEnabled() {
			next(w, r)
			return
		}

		ip := extractIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(l.window.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error": "rate limit exceeded"}`))
			return
		}

		next(w, r)
	}
}

// Cleanup removes stale entries from the rate limiter to prevent memory leaks.
// Should be called periodically (e.g., via a background goroutine).
func (l *Limiter) Cleanup() {
	if !l.IsEnabled() {
		return
	}

	cutoff := time.Now().Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	for ip, c := range l.clients {
		c.mu.Lock()
		valid := c.timestamps[:0]
		for _, ts := range c.timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		c.timestamps = valid
		c.mu.Unlock()

		// Remove client entry if no recent requests.
		if len(c.timestamps) == 0 {
			delete(l.clients, ip)
		}
	}
}

// StartCleanup starts a background goroutine that periodically cleans up
// stale rate limiter entries. Call StopCleanup to stop it.
func (l *Limiter) StartCleanup(interval time.Duration) chan struct{} {
	stop := make(chan struct{})
	if !l.IsEnabled() {
		return stop
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				l.Cleanup()
			case <-stop:
				return
			}
		}
	}()

	return stop
}
