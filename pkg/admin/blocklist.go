package admin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
)

// Blocklist holds a set of revoked certificate fingerprints (SHA-256 of DER).
type Blocklist struct {
	mu           sync.RWMutex
	fingerprints map[string]struct{}
}

// NewBlocklist creates an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{fingerprints: make(map[string]struct{})}
}

// Revoke adds a certificate fingerprint to the blocklist.
func (b *Blocklist) Revoke(fingerprint string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fingerprints[fingerprint] = struct{}{}
}

// IsRevoked checks whether a certificate fingerprint is revoked.
func (b *Blocklist) IsRevoked(fingerprint string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.fingerprints[fingerprint]
	return ok
}

// FingerprintFromPEM extracts the SHA-256 fingerprint from a PEM-encoded certificate.
func FingerprintFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// Count returns the number of revoked certificates.
func (b *Blocklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.fingerprints)
}
