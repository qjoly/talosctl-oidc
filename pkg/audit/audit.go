package audit

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventType identifies the kind of audit event.
type EventType string

const (
	// EventCertIssued is logged when an ephemeral certificate is successfully issued.
	EventCertIssued EventType = "cert_issued"

	// EventAuthFailure is logged when token validation fails.
	EventAuthFailure EventType = "auth_failure"

	// EventAuthSuccess is logged when token validation succeeds (before cert issuance).
	EventAuthSuccess EventType = "auth_success"

	// EventCertError is logged when certificate generation fails after successful auth.
	EventCertError EventType = "cert_error"
)

// Event represents a single audit log entry.
type Event struct {
	// Timestamp is when the event occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Type is the event type.
	Type EventType `json:"type"`

	// Subject is the OIDC subject identifier (sub claim).
	Subject string `json:"subject,omitempty"`

	// Email is the user's email from the OIDC token.
	Email string `json:"email,omitempty"`

	// Issuer is the OIDC issuer that authenticated the user.
	Issuer string `json:"issuer,omitempty"`

	// ClientIP is the remote address of the client.
	ClientIP string `json:"client_ip,omitempty"`

	// Roles are the Talos roles assigned to the issued certificate.
	Roles []string `json:"roles,omitempty"`

	// CertTTL is the lifetime of the issued certificate.
	CertTTL string `json:"cert_ttl,omitempty"`

	// CertExpiry is when the issued certificate expires.
	CertExpiry time.Time `json:"cert_expiry,omitempty"`

	// Error contains the error message for failure events.
	Error string `json:"error,omitempty"`

	// Detail provides additional context.
	Detail string `json:"detail,omitempty"`

	// RequestID is a unique identifier for the request (UUID v4 format).
	RequestID string `json:"request.id,omitempty"`

	// EventCategory is the ECS event category.
	EventCategory string `json:"event.category,omitempty"`

	// EventOutcome is the ECS event outcome: "success", "failure", "unknown".
	EventOutcome string `json:"event.outcome,omitempty"`

	// EventAction is the ECS event action.
	EventAction string `json:"event.action,omitempty"`

	// Severity is the log severity level.
	Severity string `json:"severity,omitempty"`
}

// NewRequestID generates a random request ID in UUID v4 format using crypto/rand.
func NewRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// SeverityForEvent returns the appropriate severity level for an event type.
func SeverityForEvent(t EventType) string {
	switch t {
	case EventCertIssued, EventAuthSuccess:
		return "INFO"
	case EventAuthFailure, EventCertError:
		return "WARN"
	default:
		return "INFO"
	}
}

// Logger writes structured audit events as JSON lines to a configured output.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	file   *os.File // non-nil when writing to a file, so we can close it

	// Listeners receive a copy of every event for in-process consumers
	// (e.g. the admin stats tracker). Access is protected by mu.
	listeners []func(Event)
}

// NewLogger creates an audit logger writing to the given destination.
//
//   - If path is empty or "-", events are written to stdout.
//   - Otherwise, events are appended to the file at path (created if needed).
func NewLogger(path string) (*Logger, error) {
	l := &Logger{}

	if path == "" || path == "-" {
		l.writer = os.Stdout
		return l, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log file %s: %w", path, err)
	}
	l.writer = f
	l.file = f

	return l, nil
}

// AddListener registers a function that will be called synchronously for every
// logged event. This is used by the admin stats tracker.
func (l *Logger) AddListener(fn func(Event)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listeners = append(l.listeners, fn)
}

// Log writes an audit event. It is safe for concurrent use.
func (l *Logger) Log(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write JSON line.
	data, err := json.Marshal(event)
	if err != nil {
		// Best-effort: log to stderr if we can't marshal.
		fmt.Fprintf(os.Stderr, "audit: failed to marshal event: %v\n", err)
		return
	}
	data = append(data, '\n')
	l.writer.Write(data) //nolint:errcheck // best-effort

	// Notify listeners.
	for _, fn := range l.listeners {
		fn(event)
	}
}

// Close flushes and closes the audit log file (if any).
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
