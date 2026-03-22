package admin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/audit"
)

func TestCertLog_PersistsOnlyCertIssued(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.log")
	logger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer logger.Close()

	cl, err := NewCertLog(path, logger)
	if err != nil {
		t.Fatalf("NewCertLog: %v", err)
	}
	defer cl.Close()

	// Non-issuance events must be ignored.
	logger.Log(audit.Event{Type: audit.EventAuthFailure, ClientIP: "10.0.0.1"})
	logger.Log(audit.Event{
		Type:            audit.EventCertIssued,
		Subject:         "user-1",
		Email:           "u@example.com",
		ClientIP:        "10.0.0.2",
		Roles:           []string{"os:reader"},
		CertTTL:         "1h0m0s",
		CertExpiry:      time.Unix(1000, 0).UTC(),
		CertFingerprint: "abc123",
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 persisted record, got %d: %q", len(lines), data)
	}
	var rec CertRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Subject != "user-1" || rec.Fingerprint != "abc123" || rec.TTL != "1h0m0s" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	// 0600 permissions for an audit artifact.
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 perms, got %v", info.Mode().Perm())
	}
}
