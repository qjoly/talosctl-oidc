package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func debug(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// AuthResult holds the result of a successful OIDC authentication.
type AuthResult struct {
	Code  string
	State string
}

// CallbackServer manages the local HTTP server that receives the OIDC callback.
type CallbackServer struct {
	port     int
	server   *http.Server
	listener net.Listener
	resultCh chan AuthResult
	errCh    chan error
}

// NewCallbackServer creates a new callback server on the given port.
func NewCallbackServer(port int) (*CallbackServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	cs := &CallbackServer{
		port:     port,
		listener: listener,
		resultCh: make(chan AuthResult, 1),
		errCh:    make(chan error, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", cs.handleCallback)

	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return cs, nil
}

// RedirectURI returns the callback URL for this server.
func (cs *CallbackServer) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", cs.port)
}

// Start begins serving in the background.
func (cs *CallbackServer) Start() {
	go func() {
		if err := cs.server.Serve(cs.listener); err != nil && err != http.ErrServerClosed {
			cs.errCh <- err
		}
	}()
}

// WaitForCallback blocks until the callback is received or the context is cancelled.
func (cs *CallbackServer) WaitForCallback(ctx context.Context) (*AuthResult, error) {
	select {
	case result := <-cs.resultCh:
		return &result, nil
	case err := <-cs.errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Shutdown gracefully stops the callback server.
func (cs *CallbackServer) Shutdown(ctx context.Context) error {
	return cs.server.Shutdown(ctx)
}

func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	debug("Received OIDC callback with query params: %v", query)

	if errMsg := query.Get("error"); errMsg != "" {
		errDesc := query.Get("error_description")
		cs.errCh <- fmt.Errorf("OIDC error: %s: %s", errMsg, errDesc)
		http.Error(w, "Authentication failed: "+errMsg, http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	state := query.Get("state")

	if code == "" {
		cs.errCh <- fmt.Errorf("no authorization code in callback")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	cs.resultCh <- AuthResult{Code: code, State: state}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>talosctl-oidc</title></head>
<body>
<h1>Authentication successful</h1>
<p>You can close this window and return to your terminal.</p>
<script>setTimeout(function() { window.close(); }, 3000);</script>
</body>
</html>`)
}

// GenerateState creates a random state parameter for CSRF protection.
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Authenticate performs the full OIDC Authorization Code + PKCE flow.
// It starts a local callback server, opens the browser, waits for the callback,
// and exchanges the code for tokens.
func Authenticate(ctx context.Context, cfg AuthConfig) (*StoredToken, error) {
	debug("Starting full OIDC authentication for issuer: %s", cfg.IssuerURL)
	// Discover the OIDC provider.
	provider, err := Discover(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	debug("Discovered provider: auth_endpoint=%s, token_endpoint=%s", provider.AuthorizationEndpoint, provider.TokenEndpoint)

	// Generate PKCE challenge.
	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, err
	}
	debug("Generated PKCE verifier and challenge (method: %s)", pkce.Method)

	// Generate state for CSRF protection.
	state, err := GenerateState()
	if err != nil {
		return nil, err
	}
	debug("Generated OIDC state: %s", state)

	// Start the local callback server.
	callbackServer, err := NewCallbackServer(cfg.CallbackPort)
	if err != nil {
		return nil, err
	}
	callbackServer.Start()
	debug("Callback server started on port %d", cfg.CallbackPort)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := callbackServer.Shutdown(shutdownCtx); err != nil {
			debug("Callback server shutdown error: %v", err)
		}
		debug("Callback server shut down")
	}()

	redirectURI := callbackServer.RedirectURI()
	debug("Using redirect URI: %s", redirectURI)

	// Build the authorization URL.
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	authURL := BuildAuthorizationURL(provider, cfg.ClientID, redirectURI, scopes, state, pkce)
	debug("Full authorization URL: %s", authURL)

	// Open browser.
	if cfg.OpenBrowser != nil {
		if err := cfg.OpenBrowser(authURL); err != nil {
			return nil, fmt.Errorf("failed to open browser: %w", err)
		}
	}

	fmt.Println("Waiting for authentication callback...")

	// Wait for the callback.
	result, err := callbackServer.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	debug("OIDC callback received successfully")

	// Verify state.
	if result.State != state {
		return nil, fmt.Errorf("state mismatch: possible CSRF attack")
	}
	debug("OIDC state verified")

	// Exchange code for tokens.
	debug("Exchanging authorization code for tokens at %s", provider.TokenEndpoint)
	tokenResp, err := ExchangeCode(ctx, provider, cfg.ClientID, cfg.ClientSecret, result.Code, redirectURI, pkce)
	if err != nil {
		return nil, err
	}
	debug("Token exchange successful (received: access_token=%v, refresh_token=%v, id_token=%v)",
		tokenResp.AccessToken != "", tokenResp.RefreshToken != "", tokenResp.IDToken != "")

	// Build stored token.
	expiresIn := tokenResp.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 3600 // Default to 1 hour if not provided.
	}
	storedToken := &StoredToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second),
		Issuer:       cfg.IssuerURL,
		ClientID:     cfg.ClientID,
	}
	debug("Token built and expires at: %s", storedToken.ExpiresAt)

	return storedToken, nil
}

// AuthConfig holds configuration for the OIDC authentication flow.
type AuthConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	CallbackPort int
	OpenBrowser  func(url string) error
}
