package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/admin"
	"github.com/qjoly/talosctl-oidc/pkg/audit"
)

func TestAdminDashboardLoginForm(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "test-token-123",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Test GET without authentication - should show login form
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Admin Login") {
		t.Error("expected body to contain login form")
	}
	if !strings.Contains(body, "Enter your admin token") {
		t.Error("expected body to contain token input prompt")
	}
	if strings.Contains(body, "Active Sessions") {
		t.Error("should not show dashboard without login")
	}
}

func TestAdminDashboardLoginSuccess(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "correct-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Submit login form with correct token
	formData := strings.NewReader("token=correct-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Should redirect to dashboard
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected redirect status %d, got %d", http.StatusSeeOther, rec.Code)
	}

	location := rec.Header().Get("Location")
	if location != "/admin/" {
		t.Errorf("expected redirect to /admin/, got %s", location)
	}

	// Check that session cookie was set
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected session cookie to be set")
	}
}

func TestAdminDashboardLoginFailure(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "correct-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Submit login form with wrong token
	formData := strings.NewReader("token=wrong-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Should return 401 but show login form with error
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Invalid admin token") {
		t.Error("expected body to contain error message")
	}
}

func TestAdminDashboardWithSession(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "test-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// First, login to get a session
	formData := strings.NewReader("token=test-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Extract session cookie
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}

	// Now access dashboard with session cookie
	req = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Talosctl OIDC Admin Dashboard") {
		t.Error("expected body to contain dashboard title")
	}
	if !strings.Contains(body, "Active Sessions") {
		t.Error("expected body to contain 'Active Sessions'")
	}
	if !strings.Contains(body, "Logout") {
		t.Error("expected body to contain logout button")
	}
}

func TestAdminDashboardWithActiveCerts(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	// Simulate some activity
	logger.Log(audit.Event{
		Type:       audit.EventCertIssued,
		Subject:    "user123",
		Email:      "user@example.com",
		ClientIP:   "192.168.1.1",
		Roles:      []string{"os:admin"},
		CertTTL:    "1h",
		CertExpiry: time.Now().Add(time.Hour),
		Timestamp:  time.Now(),
	})

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "test-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Login first
	formData := strings.NewReader("token=test-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}

	// Access dashboard
	req = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "user123") {
		t.Error("expected body to contain user subject")
	}
	if !strings.Contains(body, "user@example.com") {
		t.Error("expected body to contain user email")
	}
	if !strings.Contains(body, "192.168.1.1") {
		t.Error("expected body to contain client IP")
	}
	if !strings.Contains(body, "os:admin") {
		t.Error("expected body to contain role")
	}
}

func TestAdminDashboardLogout(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "test-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Login
	formData := strings.NewReader("token=test-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			sessionCookie = c
			break
		}
	}

	// Logout
	req = httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Should redirect to login page
	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected redirect status %d, got %d", http.StatusSeeOther, rec.Code)
	}

	// Check that cookie was cleared
	cookies = rec.Result().Cookies()
	var clearedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cookieName {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil || clearedCookie.MaxAge != -1 {
		t.Error("expected session cookie to be cleared")
	}

	// Try to access dashboard with old cookie - should show login form
	req = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "Active Sessions") {
		t.Error("should not show dashboard after logout")
	}
}

func TestAdminDashboardAPITokenStillWorks(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "api-token",
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// API endpoints should still accept Bearer token
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer api-token")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected JSON response, got %s", contentType)
	}
}

func TestAdminDashboardNoTokenConfigured(t *testing.T) {
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	tracker := admin.NewTracker(logger)

	cfg := Config{
		ListenAddr:   ":8080",
		AdminToken:   "", // No token configured
		AdminTracker: tracker,
	}

	srv := New(cfg)

	// Try to login without token configured
	formData := strings.NewReader("token=any-token")
	req := httptest.NewRequest(http.MethodPost, "/admin/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	// Should return 403
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}
