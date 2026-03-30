package admin

import (
	"sync"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/audit"
)

// CertRecord represents an issued certificate tracked in memory.
type CertRecord struct {
	Subject     string    `json:"subject"`
	Email       string    `json:"email"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	ClientIP    string    `json:"client_ip"`
	Roles       []string  `json:"roles"`
	TTL         string    `json:"ttl"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 fingerprint of the certificate
}

// Stats holds aggregate server statistics.
type Stats struct {
	// StartedAt is when the server was started.
	StartedAt time.Time `json:"started_at"`

	// Uptime is the human-readable server uptime.
	Uptime string `json:"uptime"`

	// TotalCertsIssued is the total number of certificates issued since start.
	TotalCertsIssued int64 `json:"total_certs_issued"`

	// ActiveCerts is the number of currently non-expired issued certs.
	ActiveCerts int `json:"active_certs"`

	// TotalAuthSuccesses is the total number of successful authentications.
	TotalAuthSuccesses int64 `json:"total_auth_successes"`

	// TotalAuthFailures is the total number of failed authentication attempts.
	TotalAuthFailures int64 `json:"total_auth_failures"`

	// TotalCertErrors is the total number of cert generation errors after successful auth.
	TotalCertErrors int64 `json:"total_cert_errors"`
}

// Tracker maintains an in-memory registry of issued certs and server stats.
// It subscribes to audit events and updates its state automatically.
type Tracker struct {
	mu sync.RWMutex

	startedAt        time.Time
	certs            []CertRecord
	totalCertsIssued int64
	totalAuthSuccess int64
	totalAuthFailure int64
	totalCertErrors  int64
}

// NewTracker creates a new admin tracker and registers it as a listener
// on the given audit logger.
func NewTracker(logger *audit.Logger) *Tracker {
	t := &Tracker{
		startedAt: time.Now().UTC(),
	}
	if logger != nil {
		logger.AddListener(t.handleEvent)
	}
	return t
}

// handleEvent processes an audit event and updates the tracker state.
func (t *Tracker) handleEvent(event audit.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch event.Type {
	case audit.EventCertIssued:
		t.totalCertsIssued++
		t.certs = append(t.certs, CertRecord{
			Subject:     event.Subject,
			Email:       event.Email,
			IssuedAt:    event.Timestamp,
			ExpiresAt:   event.CertExpiry,
			ClientIP:    event.ClientIP,
			Roles:       event.Roles,
			TTL:         event.CertTTL,
			Fingerprint: event.CertFingerprint,
		})
	case audit.EventAuthSuccess:
		t.totalAuthSuccess++
	case audit.EventAuthFailure:
		t.totalAuthFailure++
	case audit.EventCertError:
		t.totalCertErrors++
	}
}

// ActiveCerts returns a list of currently non-expired issued certificates.
// Expired records are pruned on every call.
func (t *Tracker) ActiveCerts() []CertRecord {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Prune expired certs.
	active := t.certs[:0]
	for _, c := range t.certs {
		if c.ExpiresAt.After(now) {
			active = append(active, c)
		}
	}
	t.certs = active

	// Return a copy.
	result := make([]CertRecord, len(active))
	copy(result, active)
	return result
}

// GetStats returns the current server statistics.
func (t *Tracker) GetStats() Stats {
	activeCerts := t.ActiveCerts()

	t.mu.RLock()
	defer t.mu.RUnlock()

	return Stats{
		StartedAt:          t.startedAt,
		Uptime:             time.Since(t.startedAt).Round(time.Second).String(),
		TotalCertsIssued:   t.totalCertsIssued,
		ActiveCerts:        len(activeCerts),
		TotalAuthSuccesses: t.totalAuthSuccess,
		TotalAuthFailures:  t.totalAuthFailure,
		TotalCertErrors:    t.totalCertErrors,
	}
}
