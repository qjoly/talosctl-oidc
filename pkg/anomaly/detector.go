package anomaly

import (
	"crypto/sha256"
	"fmt"
	"log"
	"sync"
	"time"
)

// Config holds anomaly detection configuration.
type Config struct {
	// MaxFailuresPerIP is the number of auth failures from one IP before alerting.
	MaxFailuresPerIP int
	// Window is the time window for counting failures.
	Window time.Duration
	// TokenReplayDetection enables detection of the same token used multiple times.
	TokenReplayDetection bool
	// MaxTokenUses is the max number of times a token can be used before alerting.
	MaxTokenUses int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxFailuresPerIP:     10,
		Window:               5 * time.Minute,
		TokenReplayDetection: true,
		MaxTokenUses:         3,
	}
}

type ipEntry struct {
	failures  int
	windowEnd time.Time
}

type tokenEntry struct {
	uses      int
	firstSeen time.Time
}

// Detector tracks anomalous authentication behavior.
type Detector struct {
	mu     sync.Mutex
	cfg    Config
	ipMap  map[string]*ipEntry
	tokens map[string]*tokenEntry // keyed by SHA-256 of token
}

// New creates a new Detector.
func New(cfg Config) *Detector {
	return &Detector{
		cfg:    cfg,
		ipMap:  make(map[string]*ipEntry),
		tokens: make(map[string]*tokenEntry),
	}
}

// tokenHash returns a truncated SHA-256 hash of a token for storage (avoids storing raw tokens).
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:16])
}

// RecordFailure records an authentication failure from the given IP.
// Returns true if the failure threshold has been exceeded (alert condition).
func (d *Detector) RecordFailure(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	entry, ok := d.ipMap[ip]
	if !ok || now.After(entry.windowEnd) {
		d.ipMap[ip] = &ipEntry{failures: 1, windowEnd: now.Add(d.cfg.Window)}
		return false
	}
	entry.failures++
	if entry.failures >= d.cfg.MaxFailuresPerIP {
		log.Printf("[SECURITY] ANOMALY: %d auth failures from IP %s in %s window", entry.failures, ip, d.cfg.Window)
		return true
	}
	return false
}

// RecordTokenUse records a token being used and returns true if replay is detected.
func (d *Detector) RecordTokenUse(rawToken string) bool {
	if !d.cfg.TokenReplayDetection {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	hash := tokenHash(rawToken)
	now := time.Now()
	entry, ok := d.tokens[hash]
	if !ok {
		d.tokens[hash] = &tokenEntry{uses: 1, firstSeen: now}
		return false
	}
	entry.uses++
	if entry.uses >= d.cfg.MaxTokenUses {
		log.Printf("[SECURITY] ANOMALY: token replay detected — token used %d times (hash: %s)", entry.uses, hash[:8])
		return true
	}
	return false
}

// Cleanup removes expired entries to prevent memory growth.
func (d *Detector) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for ip, entry := range d.ipMap {
		if now.After(entry.windowEnd) {
			delete(d.ipMap, ip)
		}
	}
	// Token entries older than 24h are removed.
	cutoff := now.Add(-24 * time.Hour)
	for hash, entry := range d.tokens {
		if entry.firstSeen.Before(cutoff) {
			delete(d.tokens, hash)
		}
	}
}
