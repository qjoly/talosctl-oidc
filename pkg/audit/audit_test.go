package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	l.Log(Event{
		Type:    EventAuthFailure,
		Subject: "user-123",
		Error:   "invalid token",
	})

	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatalf("unmarshaling event: %v", err)
	}
	if event.Type != EventAuthFailure {
		t.Errorf("expected type %q, got %q", EventAuthFailure, event.Type)
	}
	if event.Subject != "user-123" {
		t.Errorf("expected subject %q, got %q", "user-123", event.Subject)
	}
	if event.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestLogger_AddListener(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	received := make([]Event, 0)
	l.AddListener(func(e Event) {
		received = append(received, e)
	})

	l.Log(Event{Type: EventCertIssued, Subject: "user-456"})

	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0].Subject != "user-456" {
		t.Errorf("expected subject %q, got %q", "user-456", received[0].Subject)
	}
}

func TestLogger_MultipleListeners(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	count1 := 0
	count2 := 0
	l.AddListener(func(e Event) { count1++ })
	l.AddListener(func(e Event) { count2++ })

	l.Log(Event{Type: EventAuthSuccess, Subject: "user-789"})

	if count1 != 1 {
		t.Errorf("listener1: expected 1 call, got %d", count1)
	}
	if count2 != 1 {
		t.Errorf("listener2: expected 1 call, got %d", count2)
	}
}

func TestLogger_LogSetsTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	// Log without setting a timestamp — the logger should set it automatically.
	l.Log(Event{Type: EventCertIssued})

	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatalf("unmarshaling event: %v", err)
	}
	if event.Timestamp.IsZero() {
		t.Error("logger should set timestamp automatically when not provided")
	}
}

func TestLogger_LogPreservesExistingTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	fixedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	l.Log(Event{Type: EventCertIssued, Timestamp: fixedTime})

	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatalf("unmarshaling event: %v", err)
	}
	if !event.Timestamp.Equal(fixedTime) {
		t.Errorf("expected timestamp %v, got %v", fixedTime, event.Timestamp)
	}
}

func TestLogger_LogOutputIsJSON(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{writer: &buf}

	l.Log(Event{
		Type:    EventCertIssued,
		Subject: "user-abc",
		Roles:   []string{"os:admin"},
	})

	// Verify the output is valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if raw["type"] != string(EventCertIssued) {
		t.Errorf("expected type %q in JSON, got %v", EventCertIssued, raw["type"])
	}
}

func TestLogger_AllEventTypes(t *testing.T) {
	eventTypes := []EventType{
		EventCertIssued,
		EventAuthFailure,
		EventAuthSuccess,
		EventCertError,
	}

	for _, et := range eventTypes {
		t.Run(string(et), func(t *testing.T) {
			var buf bytes.Buffer
			l := &Logger{writer: &buf}
			l.Log(Event{Type: et})

			var event Event
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
				t.Fatalf("unmarshaling event: %v", err)
			}
			if event.Type != et {
				t.Errorf("expected type %q, got %q", et, event.Type)
			}
		})
	}
}
