// Package allowlist provides IP allowlisting functionality for the HTTP server.
// It supports CIDR notation and individual IP addresses.
package allowlist

import (
	"net"
	"net/http"
	"strings"
)

// Allowlist manages a list of allowed IP addresses and CIDR ranges.
type Allowlist struct {
	nets []net.IPNet
	ips  []net.IP
}

// New creates a new allowlist from a list of CIDR strings or IP addresses.
// If the list is empty, the allowlist allows all IPs (IsEnabled returns false).
func New(allowed []string) (*Allowlist, error) {
	if len(allowed) == 0 {
		return &Allowlist{}, nil
	}

	a := &Allowlist{}
	for _, s := range allowed {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		// Try to parse as CIDR first.
		_, ipnet, err := net.ParseCIDR(s)
		if err == nil {
			a.nets = append(a.nets, *ipnet)
			continue
		}

		// Try to parse as individual IP.
		ip := net.ParseIP(s)
		if ip != nil {
			a.ips = append(a.ips, ip)
			continue
		}

		return nil, &ParseError{Input: s, Err: err}
	}

	return a, nil
}

// ParseError represents an error parsing an allowlist entry.
type ParseError struct {
	Input string
	Err   error
}

func (e *ParseError) Error() string {
	return "invalid IP or CIDR: " + e.Input
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// IsEnabled returns true if the allowlist has entries and will perform checks.
func (a *Allowlist) IsEnabled() bool {
	return a != nil && (len(a.nets) > 0 || len(a.ips) > 0)
}

// Allowed checks if the given IP address is in the allowlist.
// If the allowlist is not enabled, it always returns true.
func (a *Allowlist) Allowed(ip string) bool {
	if !a.IsEnabled() {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check individual IPs.
	for _, allowedIP := range a.ips {
		if allowedIP.Equal(parsedIP) {
			return true
		}
	}

	// Check CIDR ranges.
	for _, net := range a.nets {
		if net.Contains(parsedIP) {
			return true
		}
	}

	return false
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

// Middleware returns an HTTP middleware that checks IP allowlisting.
// If the IP is not allowed, it returns 403 Forbidden.
func (a *Allowlist) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.IsEnabled() {
			next(w, r)
			return
		}

		ip := extractIP(r)
		if !a.Allowed(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "IP not allowed"}`))
			return
		}

		next(w, r)
	}
}
