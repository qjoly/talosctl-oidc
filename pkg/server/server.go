package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/admin"
	"github.com/qjoly/talosctl-oidc/pkg/allowlist"
	"github.com/qjoly/talosctl-oidc/pkg/audit"
	"github.com/qjoly/talosctl-oidc/pkg/certsign"
	"github.com/qjoly/talosctl-oidc/pkg/oidc"
	"github.com/qjoly/talosctl-oidc/pkg/ratelimit"
)

func debug(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Config holds the configuration for the cert exchange server.
type Config struct {
	// ListenAddr is the address to listen on (e.g. ":8443").
	ListenAddr string

	// CA is the parsed Talos CA used to sign ephemeral client certificates.
	CA *certsign.CA

	// CertTTL is the lifetime of issued client certificates.
	CertTTL time.Duration

	// Roles are the Talos roles to assign to issued certificates.
	Roles []string

	// IssuerURL is the OIDC provider issuer URL for token validation.
	IssuerURL string

	// ClientID is the expected OIDC client ID (audience).
	ClientID string

	// ClientSecret is the OIDC client secret, required for HS256-signed tokens.
	ClientSecret string

	// Endpoints are the Talos node endpoints to include in the response.
	Endpoints []string

	// TLSCertFile is the path to a TLS certificate file.
	// When set (together with TLSKeyFile), the server serves HTTPS with these certs.
	TLSCertFile string

	// TLSKeyFile is the path to a TLS private key file.
	TLSKeyFile string

	// Insecure, when true, serves plain HTTP without TLS.
	// A warning is logged at startup.
	Insecure bool

	// DataDir is an optional directory path for persisting the self-signed TLS
	// certificate across restarts. When set and the server is in self-signed mode,
	// the CA and server certificate are saved to this directory on first run and
	// reloaded on subsequent starts. When empty, certificates are generated in
	// memory and lost on restart.
	DataDir string

	// AuditLogger is an optional structured audit logger. When non-nil, the
	// server emits audit events for every authentication attempt and certificate
	// issuance.
	AuditLogger *audit.Logger

	// AdminToken, when set, protects the /admin/* endpoints with a bearer token.
	AdminToken string

	// AdminTracker is the in-memory tracker for issued certs and stats.
	// When non-nil, the /admin/certs and /admin/stats endpoints are enabled.
	AdminTracker *admin.Tracker

	// RateLimiter is an optional rate limiter for the /exchange endpoint.
	// When non-nil, requests are rate-limited per IP.
	RateLimiter *ratelimit.Limiter

	// Allowlist is an optional IP allowlist for the /exchange endpoint.
	// When non-nil, only IPs in the allowlist can access the endpoint.
	Allowlist *allowlist.Allowlist
}

// CertResponse is the JSON response returned to clients after successful token exchange.
type CertResponse struct {
	CA        string   `json:"ca"`
	Cert      string   `json:"cert"`
	Key       string   `json:"key"`
	Endpoints []string `json:"endpoints"`
	TTL       int      `json:"ttl_seconds"`
}

// ErrorResponse is the JSON error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Server is the cert exchange HTTP server.
type Server struct {
	cfg        Config
	httpServer *http.Server

	// selfSignedCAPEM holds the PEM-encoded CA certificate when using self-signed TLS mode.
	// Exposed via the /ca endpoint so clients can fetch it.
	selfSignedCAPEM []byte
}

// New creates a new cert exchange server.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg}

	mux := http.NewServeMux()

	// Apply rate limiting and IP allowlist middleware to /exchange endpoint.
	exchangeHandler := http.HandlerFunc(s.handleExchange)
	if cfg.Allowlist != nil && cfg.Allowlist.IsEnabled() {
		exchangeHandler = cfg.Allowlist.Middleware(exchangeHandler)
	}
	if cfg.RateLimiter != nil && cfg.RateLimiter.IsEnabled() {
		exchangeHandler = cfg.RateLimiter.Middleware(exchangeHandler)
	}
	mux.HandleFunc("/exchange", exchangeHandler)

	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/ca", s.handleCA)

	// Admin endpoints (only registered when a tracker is configured).
	if cfg.AdminTracker != nil {
		mux.HandleFunc("/admin/stats", s.requireAdminToken(s.handleAdminStats))
		mux.HandleFunc("/admin/certs", s.requireAdminToken(s.handleAdminCerts))
	}

	s.httpServer = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return s
}

// Start begins listening. It blocks until the server is shut down.
//
// TLS mode selection:
//  1. TLSCertFile + TLSKeyFile set -> HTTPS with provided certificate
//  2. Insecure=true                -> plain HTTP (warning logged)
//  3. Default                      -> HTTPS with auto-generated self-signed certificate
func (s *Server) Start() error {
	log.Printf("Cert exchange server listening on %s", s.cfg.ListenAddr)
	log.Printf("OIDC issuer: %s", s.cfg.IssuerURL)
	log.Printf("Certificate TTL: %s", s.cfg.CertTTL)
	log.Printf("Roles: %v", s.cfg.Roles)
	log.Printf("Endpoints: %v", s.cfg.Endpoints)

	// Mode 1: user-provided TLS cert + key.
	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		log.Printf("TLS mode: using provided certificate (%s)", s.cfg.TLSCertFile)
		return s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}

	// Mode 2: insecure plain HTTP.
	if s.cfg.Insecure {
		log.Printf("WARNING: serving plain HTTP (insecure mode) - do NOT use in production")
		return s.httpServer.ListenAndServe()
	}

	// Mode 3 (default): generate a self-signed TLS certificate.
	log.Printf("TLS mode: generating self-signed certificate")
	tlsCfg, err := s.generateSelfSignedTLS()
	if err != nil {
		return fmt.Errorf("generating self-signed TLS certificate: %w", err)
	}

	s.httpServer.TLSConfig = tlsCfg

	// ListenAndServeTLS with empty cert/key paths uses the TLSConfig we just set.
	return s.httpServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// generateSelfSignedTLS creates or loads a self-signed CA and server certificate.
//
// When DataDir is set, the CA and server certificate are persisted to disk so
// they survive restarts. The files used are:
//
//	<DataDir>/ca.crt       - CA certificate PEM
//	<DataDir>/ca.key       - CA private key PEM
//	<DataDir>/server.crt   - Server certificate PEM
//	<DataDir>/server.key   - Server private key PEM
//
// When DataDir is empty, everything is generated in memory.
func (s *Server) generateSelfSignedTLS() (*tls.Config, error) {
	if s.cfg.DataDir != "" {
		return s.loadOrGenerateSelfSignedTLS()
	}
	return s.generateSelfSignedTLSInMemory()
}

// selfSignedPaths returns the file paths for persisted self-signed cert material.
func (s *Server) selfSignedPaths() (caCrt, caKey, srvCrt, srvKey string) {
	d := s.cfg.DataDir
	return filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key"),
		filepath.Join(d, "server.crt"), filepath.Join(d, "server.key")
}

// loadOrGenerateSelfSignedTLS tries to load existing self-signed certs from
// DataDir. If they don't exist, it generates new ones and saves them.
func (s *Server) loadOrGenerateSelfSignedTLS() (*tls.Config, error) {
	caCrtPath, caKeyPath, srvCrtPath, srvKeyPath := s.selfSignedPaths()

	// Check if all four files exist.
	allExist := fileExists(caCrtPath) && fileExists(caKeyPath) &&
		fileExists(srvCrtPath) && fileExists(srvKeyPath)

	if allExist {
		log.Printf("Loading persisted self-signed TLS certificates from %s", s.cfg.DataDir)
		return s.loadPersistedSelfSignedTLS(caCrtPath, caKeyPath, srvCrtPath, srvKeyPath)
	}

	// Generate fresh certificates.
	log.Printf("No persisted certificates found in %s, generating new ones", s.cfg.DataDir)
	tlsCfg, caPEM, caKeyPEM, srvCertPEM, srvKeyPEM, err := s.generateSelfSignedMaterial()
	if err != nil {
		return nil, err
	}

	// Ensure the data directory exists.
	if err := os.MkdirAll(s.cfg.DataDir, 0o700); err != nil {
		log.Printf("WARNING: cannot create data directory %s: %v — falling back to in-memory TLS (certificates will not persist across restarts)", s.cfg.DataDir, err)
		return tlsCfg, nil
	}

	// Write all four files.
	for _, f := range []struct {
		path string
		data []byte
	}{
		{caCrtPath, caPEM},
		{caKeyPath, caKeyPEM},
		{srvCrtPath, srvCertPEM},
		{srvKeyPath, srvKeyPEM},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			log.Printf("WARNING: cannot write %s: %v — falling back to in-memory TLS", f.path, err)
			return tlsCfg, nil
		}
	}

	log.Printf("Persisted self-signed TLS certificates to %s", s.cfg.DataDir)
	return tlsCfg, nil
}

// loadPersistedSelfSignedTLS loads previously saved self-signed TLS material.
func (s *Server) loadPersistedSelfSignedTLS(caCrtPath, caKeyPath, srvCrtPath, srvKeyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caCrtPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert %s: %w", caCrtPath, err)
	}
	s.selfSignedCAPEM = caPEM

	// Log fingerprint of the loaded CA.
	block, _ := pem.Decode(caPEM)
	if block != nil {
		fingerprint := sha256.Sum256(block.Bytes)
		log.Printf("Self-signed CA fingerprint (SHA-256): %x", fingerprint)
		log.Printf("Self-signed CA PEM (use with --server-ca on the login command):\n%s", string(caPEM))
	}

	tlsCert, err := tls.LoadX509KeyPair(srvCrtPath, srvKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading server key pair from %s / %s: %w", srvCrtPath, srvKeyPath, err)
	}

	// Verify that the CA key can still be loaded (sanity check).
	if _, err := os.ReadFile(caKeyPath); err != nil {
		return nil, fmt.Errorf("reading CA key %s: %w", caKeyPath, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateSelfSignedMaterial generates a self-signed CA and server certificate,
// returning the tls.Config and all PEM-encoded material for optional persistence.
func (s *Server) generateSelfSignedMaterial() (tlsCfg *tls.Config, caPEM, caKeyPEM, srvCertPEM, srvKeyPEM []byte, err error) {
	// Generate CA key and certificate.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("generating CA key: %w", err)
	}

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("generating CA serial: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "talosctl-oidc self-signed CA",
			Organization: []string{"talosctl-oidc"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	// Encode CA to PEM.
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	s.selfSignedCAPEM = caPEM

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling CA key: %w", err)
	}
	caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	// Log the CA fingerprint and PEM.
	fingerprint := sha256.Sum256(caCertDER)
	log.Printf("Self-signed CA fingerprint (SHA-256): %x", fingerprint)
	log.Printf("Self-signed CA PEM (use with --server-ca on the login command):\n%s", string(caPEM))

	// Generate server key and certificate signed by the CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("generating server key: %w", err)
	}

	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("generating server serial: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   "talosctl-oidc server",
			Organization: []string{"talosctl-oidc"},
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Try to add the listen host as a SAN if it looks like an IP or hostname.
	if host, _, splitErr := net.SplitHostPort(s.cfg.ListenAddr); splitErr == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
		} else {
			serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
		}
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("creating server certificate: %w", err)
	}

	srvCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling server key: %w", err)
	}
	srvKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	tlsKeyPair, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("creating TLS key pair: %w", err)
	}

	tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{tlsKeyPair},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsCfg, caPEM, caKeyPEM, srvCertPEM, srvKeyPEM, nil
}

// generateSelfSignedTLSInMemory generates a self-signed certificate in memory only
// (no persistence). Used when DataDir is not set.
func (s *Server) generateSelfSignedTLSInMemory() (*tls.Config, error) {
	tlsCfg, _, _, _, _, err := s.generateSelfSignedMaterial()
	return tlsCfg, err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// handleHealth returns a 200 OK for health checks.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handleCA returns the self-signed CA PEM when running in self-signed mode.
// This allows clients to fetch the CA and trust it without out-of-band transfer.
// In non-self-signed modes, it returns 404.
func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if len(s.selfSignedCAPEM) == 0 {
		writeError(w, http.StatusNotFound, "CA endpoint only available in self-signed TLS mode")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.selfSignedCAPEM)
}

// handleExchange validates an OIDC token and returns an ephemeral client certificate.
//
// Request: POST /exchange
// Body: {"id_token": "eyJ..."}
// Response: {"ca": "...", "cert": "...", "key": "...", "endpoints": [...], "ttl_seconds": 3600}
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	debug("Received /exchange request from %s", r.RemoteAddr)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	clientIP := r.RemoteAddr

	// Parse request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		debug("Failed to read request body: %v", err)
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		debug("Failed to unmarshal JSON body: %v", err)
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.IDToken == "" {
		debug("ID token missing in request body")
		writeError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	debug("Validating OIDC ID token...")
	// Validate the OIDC token.
	tc, err := s.validateToken(r.Context(), req.IDToken)
	if err != nil {
		debug("Token validation failed: %v", err)
		log.Printf("Token validation failed: %v", err)
		s.auditLog(audit.Event{
			Type:     audit.EventAuthFailure,
			ClientIP: clientIP,
			Error:    err.Error(),
		})
		writeError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}
	debug("Token validated successfully for user: %s (%s)", tc.Subject, tc.Email)

	// Auth succeeded.
	s.auditLog(audit.Event{
		Type:     audit.EventAuthSuccess,
		Subject:  tc.Subject,
		Email:    tc.Email,
		Issuer:   tc.Issuer,
		ClientIP: clientIP,
	})

	debug("Generating ephemeral client certificate for roles: %v", s.cfg.Roles)
	// Generate ephemeral client certificate.
	clientCert, err := certsign.GenerateClientCert(s.cfg.CA, s.cfg.Roles, s.cfg.CertTTL)
	if err != nil {
		debug("Certificate generation failed: %v", err)
		log.Printf("Certificate generation failed: %v", err)
		s.auditLog(audit.Event{
			Type:     audit.EventCertError,
			Subject:  tc.Subject,
			Email:    tc.Email,
			ClientIP: clientIP,
			Error:    err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to generate certificate")
		return
	}
	debug("Certificate generated successfully")

	certExpiry := time.Now().Add(s.cfg.CertTTL)

	resp := CertResponse{
		CA:        string(clientCert.CaPEM),
		Cert:      string(clientCert.CertPEM),
		Key:       string(clientCert.KeyPEM),
		Endpoints: s.cfg.Endpoints,
		TTL:       int(s.cfg.CertTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	s.auditLog(audit.Event{
		Type:       audit.EventCertIssued,
		Subject:    tc.Subject,
		Email:      tc.Email,
		Issuer:     tc.Issuer,
		ClientIP:   clientIP,
		Roles:      s.cfg.Roles,
		CertTTL:    s.cfg.CertTTL.String(),
		CertExpiry: certExpiry,
	})

	log.Printf("Issued ephemeral certificate (TTL: %s)", s.cfg.CertTTL)
}

// tokenClaims holds extracted identity information from a validated token.
type tokenClaims struct {
	Subject string
	Email   string
	Issuer  string
}

// validateToken verifies the OIDC ID token against the provider.
// It checks:
// - The token signature via the provider's JWKS
// - The issuer matches the configured issuer
// - The audience contains the configured client ID
// - The token is not expired
//
// On success it returns the extracted identity claims.
func (s *Server) validateToken(ctx context.Context, idToken string) (*tokenClaims, error) {
	debug("Starting token validation for issuer: %s", s.cfg.IssuerURL)
	// Discover the OIDC provider to get the JWKS URI.
	provider, err := oidc.Discover(ctx, s.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	debug("OIDC provider discovered, fetching JWKS from %s", provider.JWKSURI)

	// Fetch the JWKS.
	jwks, err := oidc.FetchJWKS(ctx, provider.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	debug("JWKS fetched (keys: %d)", len(jwks.Keys))

	// Parse and validate the token.
	debug("Verifying ID token signature and claims (ClientID: %s)...", s.cfg.ClientID)
	claims, err := oidc.ValidateIDToken(idToken, jwks, s.cfg.IssuerURL, s.cfg.ClientID, s.cfg.ClientSecret)
	if err != nil {
		return nil, err
	}
	debug("ID token verification successful")

	tc := &tokenClaims{}
	if sub, ok := claims["sub"].(string); ok {
		tc.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		tc.Email = email
	}
	if iss, ok := claims["iss"].(string); ok {
		tc.Issuer = iss
	}

	// Log the authenticated user.
	if tc.Email != "" {
		log.Printf("Authenticated user: %s (%s)", tc.Subject, tc.Email)
	} else {
		log.Printf("Authenticated user: %s", tc.Subject)
	}

	return tc, nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}

// auditLog emits an audit event if an audit logger is configured.
func (s *Server) auditLog(event audit.Event) {
	if s.cfg.AuditLogger != nil {
		s.cfg.AuditLogger.Log(event)
	}
}

// requireAdminToken wraps a handler with bearer token authentication.
// If no AdminToken is configured, all requests are rejected with 403.
func (s *Server) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			writeError(w, http.StatusForbidden, "admin API is disabled (no TALOSCTL_OIDC_ADMIN_TOKEN configured)")
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, "invalid Authorization header (expected Bearer token)")
			return
		}

		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) != 1 {
			writeError(w, http.StatusForbidden, "invalid admin token")
			return
		}

		next(w, r)
	}
}

// handleAdminStats returns aggregate server statistics.
//
// GET /admin/stats
// Response: {"started_at": "...", "uptime": "...", "total_certs_issued": N, ...}
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	stats := s.cfg.AdminTracker.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAdminCerts returns the list of currently active (non-expired) issued certificates.
//
// GET /admin/certs
// Response: [{"subject": "...", "email": "...", "issued_at": "...", ...}, ...]
func (s *Server) handleAdminCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	certs := s.cfg.AdminTracker.ActiveCerts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}
