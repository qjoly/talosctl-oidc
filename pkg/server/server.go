package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/qjoly/talosctl-oidc/pkg/certsign"
	"github.com/qjoly/talosctl-oidc/pkg/oidc"
)

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
}

// New creates a new cert exchange server.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/exchange", s.handleExchange)
	mux.HandleFunc("/healthz", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s
}

// Start begins listening. It blocks until the server is shut down.
func (s *Server) Start() error {
	log.Printf("Cert exchange server listening on %s", s.cfg.ListenAddr)
	log.Printf("OIDC issuer: %s", s.cfg.IssuerURL)
	log.Printf("Certificate TTL: %s", s.cfg.CertTTL)
	log.Printf("Roles: %v", s.cfg.Roles)
	log.Printf("Endpoints: %v", s.cfg.Endpoints)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// handleHealth returns a 200 OK for health checks.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

// handleExchange validates an OIDC token and returns an ephemeral client certificate.
//
// Request: POST /exchange
// Body: {"id_token": "eyJ..."}
// Response: {"ca": "...", "cert": "...", "key": "...", "endpoints": [...], "ttl_seconds": 3600}
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.IDToken == "" {
		writeError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	// Validate the OIDC token.
	if err := s.validateToken(r.Context(), req.IDToken); err != nil {
		log.Printf("Token validation failed: %v", err)
		writeError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}

	// Generate ephemeral client certificate.
	clientCert, err := certsign.GenerateClientCert(s.cfg.CA, s.cfg.Roles, s.cfg.CertTTL)
	if err != nil {
		log.Printf("Certificate generation failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to generate certificate")
		return
	}

	resp := CertResponse{
		CA:        string(clientCert.CaPEM),
		Cert:      string(clientCert.CertPEM),
		Key:       string(clientCert.KeyPEM),
		Endpoints: s.cfg.Endpoints,
		TTL:       int(s.cfg.CertTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("Issued ephemeral certificate (TTL: %s)", s.cfg.CertTTL)
}

// validateToken verifies the OIDC ID token against the provider.
// It checks:
// - The token signature via the provider's JWKS
// - The issuer matches the configured issuer
// - The audience contains the configured client ID
// - The token is not expired
func (s *Server) validateToken(ctx context.Context, idToken string) error {
	// Discover the OIDC provider to get the JWKS URI.
	provider, err := oidc.Discover(ctx, s.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// Fetch the JWKS.
	jwks, err := oidc.FetchJWKS(ctx, provider.JWKSURI)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}

	// Parse and validate the token.
	claims, err := oidc.ValidateIDToken(idToken, jwks, s.cfg.IssuerURL, s.cfg.ClientID, s.cfg.ClientSecret)
	if err != nil {
		return err
	}

	// Log the authenticated user.
	if sub, ok := claims["sub"].(string); ok {
		email, _ := claims["email"].(string)
		if email != "" {
			log.Printf("Authenticated user: %s (%s)", sub, email)
		} else {
			log.Printf("Authenticated user: %s", sub)
		}
	}

	return nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}
