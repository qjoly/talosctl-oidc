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
	nets    []net.IPNet
	ips     []net.IP
	trusted []net.IPNet // Trusted proxy networks; X-Forwarded-For is only honored from these.
}

// New creates a new allowlist from a list of CIDR strings or IP addresses.
// If the list is empty, the allowlist allows all IPs (IsEnabled returns false).
//
// trustedProxies lists CIDRs/IPs of reverse proxies that are allowed to set
// X-Forwarded-For. When empty, X-Forwarded-For is never trusted and the
// direct connection address is used instead.
func New(allowed, trustedProxies []string) (*Allowlist, error) {
	a := &Allowlist{}

	trusted, err := parseNets(trustedProxies)
	if err != nil {
		return nil, err
	}
	a.trusted = trusted

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

// parseNets parses a list of CIDRs or single IPs into networks. A bare IP is
// treated as a host network (/32 or /128).
func parseNets(entries []string) ([]net.IPNet, error) {
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
			continue
		}
		return nil, &ParseError{Input: s}
	}
	return nets, nil
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

// extractIP returns the client IP for allowlist checks.
//
// X-Forwarded-For is attacker-controlled, so it is only honored when the
// direct connection peer (RemoteAddr) is a configured trusted proxy. In that
// case we walk the header right-to-left and return the first address that is
// not itself a trusted proxy — the real client as seen by our proxy chain.
// Otherwise the direct peer address is used, which cannot be spoofed.
func (a *Allowlist) extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if a.isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if !a.isTrustedProxy(ip) {
					return ip
				}
			}
		}
	}

	return host
}

// isTrustedProxy reports whether ip belongs to a configured trusted proxy network.
func (a *Allowlist) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range a.trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Middleware returns an HTTP middleware that checks IP allowlisting.
// If the IP is not allowed, it returns 403 Forbidden.
func (a *Allowlist) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.IsEnabled() {
			next(w, r)
			return
		}

		ip := a.extractIP(r)
		if !a.Allowed(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "IP not allowed"}`))
			return
		}

		next(w, r)
	}
}
