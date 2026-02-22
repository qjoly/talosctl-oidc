package server

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/admin"
)

//go:embed templates/admin.html
var adminHTMLTemplate string

// sessionTimeout defines how long a session remains valid
const sessionTimeout = 24 * time.Hour

// brute force protection constants
const (
	maxLoginAttempts    = 5                // max failed attempts before lockout
	lockoutDuration     = 15 * time.Minute // how long to lock out
	failedAttemptWindow = 15 * time.Minute // window for counting failed attempts
)

// AdminPageData holds the data for the admin dashboard template.
type AdminPageData struct {
	Stats       admin.Stats
	Certs       []admin.CertRecord
	CurrentTime time.Time
	LoggedIn    bool
	Error       string
}

// session represents an authenticated admin session
type session struct {
	token     string
	createdAt time.Time
}

// sessionStore manages active sessions
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

// newSessionStore creates a new session store
func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*session),
	}
}

// generateToken creates a random session token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// create creates a new session and returns the session token
func (s *sessionStore) create() (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean up expired sessions
	now := time.Now()
	for id, sess := range s.sessions {
		if now.Sub(sess.createdAt) > sessionTimeout {
			delete(s.sessions, id)
		}
	}

	s.sessions[token] = &session{
		token:     token,
		createdAt: now,
	}

	return token, nil
}

// validate checks if a session token is valid
func (s *sessionStore) validate(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, exists := s.sessions[token]
	if !exists {
		return false
	}

	// Check if session is expired
	if time.Since(sess.createdAt) > sessionTimeout {
		return false
	}

	return true
}

// delete removes a session
func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// loginAttempt tracks failed login attempts for an IP
type loginAttempt struct {
	count     int
	lastFail  time.Time
	lockedOut bool
	lockoutAt time.Time
}

// bruteForceProtector tracks failed login attempts per IP
type bruteForceProtector struct {
	mu       sync.RWMutex
	attempts map[string]*loginAttempt
}

// newBruteForceProtector creates a new brute force protector
func newBruteForceProtector() *bruteForceProtector {
	return &bruteForceProtector{
		attempts: make(map[string]*loginAttempt),
	}
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if there are multiple
		if idx := strings.Index(xff, ","); idx != -1 {
			xff = strings.TrimSpace(xff[:idx])
		}
		return xff
	}

	// Check X-Real-Ip header
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLockedOut checks if the IP is currently locked out
func (b *bruteForceProtector) isLockedOut(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	attempt, exists := b.attempts[ip]
	if !exists {
		return false
	}

	// Check if lockout has expired
	if attempt.lockedOut {
		if time.Since(attempt.lockoutAt) > lockoutDuration {
			// Lockout expired, reset
			return false
		}
		return true
	}

	return false
}

// recordFailed records a failed login attempt
func (b *bruteForceProtector) recordFailed(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	attempt, exists := b.attempts[ip]
	if !exists {
		attempt = &loginAttempt{}
		b.attempts[ip] = attempt
	}

	now := time.Now()

	// Reset count if the window has passed
	if now.Sub(attempt.lastFail) > failedAttemptWindow {
		attempt.count = 0
		attempt.lockedOut = false
	}

	attempt.count++
	attempt.lastFail = now

	// Check if we should lock out
	if attempt.count >= maxLoginAttempts {
		attempt.lockedOut = true
		attempt.lockoutAt = now
	}
}

// recordSuccess clears failed attempts for an IP after successful login
func (b *bruteForceProtector) recordSuccess(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.attempts, ip)
}

// getRemainingLockoutTime returns how long the IP is still locked out
func (b *bruteForceProtector) getRemainingLockoutTime(ip string) time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()

	attempt, exists := b.attempts[ip]
	if !exists || !attempt.lockedOut {
		return 0
	}

	remaining := lockoutDuration - time.Since(attempt.lockoutAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cookieName is the name of the session cookie
const cookieName = "talosctl_oidc_admin_session"

// getSessionToken extracts the session token from the request
func getSessionToken(r *http.Request) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// handleAdminDashboard serves the HTML admin dashboard page.
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	// Initialize session store if needed
	if s.adminSessions == nil {
		s.adminSessions = newSessionStore()
	}

	// Check if user is logged in via session
	sessionToken := getSessionToken(r)
	isLoggedIn := sessionToken != "" && s.adminSessions.validate(sessionToken)

	data := AdminPageData{
		CurrentTime: time.Now().UTC(),
		LoggedIn:    isLoggedIn,
	}

	if isLoggedIn {
		// Get stats and certs from tracker
		data.Stats = s.cfg.AdminTracker.GetStats()
		data.Certs = s.cfg.AdminTracker.ActiveCerts()
	}

	// Parse and execute template
	tmpl, err := template.New("admin").Parse(adminHTMLTemplate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to parse template")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// handleAdminLogin processes the login form submission
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Check if admin token is configured
	if s.cfg.AdminToken == "" {
		writeError(w, http.StatusForbidden, "admin API is disabled (no TALOSCTL_OIDC_ADMIN_TOKEN configured)")
		return
	}

	// Initialize brute force protector if needed
	if s.bruteForce == nil {
		s.bruteForce = newBruteForceProtector()
	}

	// Get client IP
	clientIP := getClientIP(r)

	// Check if IP is locked out
	if s.bruteForce.isLockedOut(clientIP) {
		remaining := s.bruteForce.getRemainingLockoutTime(clientIP)
		data := AdminPageData{
			CurrentTime: time.Now().UTC(),
			LoggedIn:    false,
			Error:       fmt.Sprintf("Too many failed attempts. Please try again in %d minutes.", int(remaining.Minutes())+1),
		}

		tmpl, _ := template.New("admin").Parse(adminHTMLTemplate)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		tmpl.Execute(w, data)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	submittedToken := r.FormValue("token")

	// Validate token using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(submittedToken), []byte(s.cfg.AdminToken)) != 1 {
		// Record failed attempt
		s.bruteForce.recordFailed(clientIP)

		// Invalid token - show error on login page
		data := AdminPageData{
			CurrentTime: time.Now().UTC(),
			LoggedIn:    false,
			Error:       "Invalid admin token",
		}

		tmpl, _ := template.New("admin").Parse(adminHTMLTemplate)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		tmpl.Execute(w, data)
		return
	}

	// Token is valid - clear failed attempts
	s.bruteForce.recordSuccess(clientIP)

	// Create session
	if s.adminSessions == nil {
		s.adminSessions = newSessionStore()
	}

	sessionToken, err := s.adminSessions.create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	// Set session cookie
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    sessionToken,
		Path:     "/admin/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.HasPrefix(r.Proto, "HTTPS"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTimeout.Seconds()),
	}
	http.SetCookie(w, cookie)

	// Redirect to dashboard
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// handleAdminLogout handles logout requests
func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get and invalidate session
	sessionToken := getSessionToken(r)
	if sessionToken != "" && s.adminSessions != nil {
		s.adminSessions.delete(sessionToken)
	}

	// Clear cookie
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/admin/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)

	// Redirect to login page
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// requireAdminSession wraps a handler with session validation
func (s *Server) requireAdminSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow GET requests to the root /admin/ without session (will show login form)
		if r.Method == http.MethodGet && r.URL.Path == "/admin/" {
			next(w, r)
			return
		}

		// Check for session
		if s.adminSessions == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		sessionToken := getSessionToken(r)
		if sessionToken == "" || !s.adminSessions.validate(sessionToken) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(w, r)
	}
}
