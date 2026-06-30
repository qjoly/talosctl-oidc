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
	trusted  []net.IPNet // Trusted proxy networks; X-Forwarded-For is only honored from these.
}

// client tracks request timestamps for a single IP.
type client struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// New creates a new rate limiter with the specified request limit and window.
// If requests is 0, rate limiting is disabled.
//
// trustedProxies lists CIDRs/IPs of reverse proxies allowed to set
// X-Forwarded-For. When empty, X-Forwarded-For is never trusted and the
// direct connection address is used as the rate-limit key.
func New(requests int, window time.Duration, trustedProxies []string) *Limiter {
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		requests: requests,
		window:   window,
		clients:  make(map[string]*client),
		trusted:  parseNets(trustedProxies),
	}
}

// parseNets parses a list of CIDRs or single IPs into networks. A bare IP is
// treated as a host network (/32 or /128). Unparseable entries are skipped.
func parseNets(entries []string) []net.IPNet {
	var nets []net.IPNet
	for _, s := range entries {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, *ipnet)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
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

// extractIP returns the rate-limit key (client IP) for the request.
//
// X-Forwarded-For is attacker-controlled, so it is only honored when the
// direct connection peer (RemoteAddr) is a configured trusted proxy. In that
// case we walk the header right-to-left and return the first address that is
// not itself a trusted proxy — the real client as seen by our proxy chain.
// Otherwise the direct peer address is used, which cannot be spoofed to mint
// fresh buckets or exhaust another client's bucket.
func (l *Limiter) extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if l.isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if !l.isTrustedProxy(ip) {
					return ip
				}
			}
		}
	}

	return host
}

// isTrustedProxy reports whether ip belongs to a configured trusted proxy network.
func (l *Limiter) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range l.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Middleware returns an HTTP middleware that applies rate limiting.
// If the limit is exceeded, it returns 429 Too Many Requests.
func (l *Limiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.IsEnabled() {
			next(w, r)
			return
		}

		ip := l.extractIP(r)
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
