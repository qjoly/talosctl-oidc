package admin

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/qjoly/talosctl-oidc/pkg/audit"
)

// CertLog is a persistent, append-only log of issued certificates. It records
// one JSON Lines entry per successful issuance so that access reviews survive
// server restarts (the in-memory Tracker does not).
//
// CertLog subscribes to the audit logger just like Tracker: every
// EventCertIssued is persisted as a CertRecord.
type CertLog struct {
	mu   sync.Mutex
	file *os.File
}

// NewCertLog opens (or creates) an append-only certificate log at path with
// 0600 permissions and registers it as a listener on the audit logger.
func NewCertLog(path string, logger *audit.Logger) (*CertLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening cert log: %w", err)
	}
	l := &CertLog{file: f}
	if logger != nil {
		logger.AddListener(l.handleEvent)
	}
	return l, nil
}

// handleEvent persists a CertRecord for every certificate issuance event.
func (l *CertLog) handleEvent(event audit.Event) {
	if event.Type != audit.EventCertIssued {
		return
	}
	_ = l.append(CertRecord{
		Subject:     event.Subject,
		Email:       event.Email,
		IssuedAt:    event.Timestamp,
		ExpiresAt:   event.CertExpiry,
		ClientIP:    event.ClientIP,
		Roles:       event.Roles,
		TTL:         event.CertTTL,
		Fingerprint: event.CertFingerprint,
	})
}

// append writes a certificate record to the log as a single JSON line.
func (l *CertLog) append(rec CertRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling cert record: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.file.Write(append(data, '\n'))
	return err
}

// Close closes the log file.
func (l *CertLog) Close() error {
	return l.file.Close()
}
