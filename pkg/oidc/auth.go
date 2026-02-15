package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"
)

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
	// Discover the OIDC provider.
	provider, err := Discover(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// Generate PKCE challenge.
	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, err
	}

	// Generate state for CSRF protection.
	state, err := GenerateState()
	if err != nil {
		return nil, err
	}

	// Start the local callback server.
	callbackServer, err := NewCallbackServer(cfg.CallbackPort)
	if err != nil {
		return nil, err
	}
	callbackServer.Start()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		callbackServer.Shutdown(shutdownCtx)
	}()

	redirectURI := callbackServer.RedirectURI()

	// Build the authorization URL.
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	authURL := BuildAuthorizationURL(provider, cfg.ClientID, redirectURI, scopes, state, pkce)

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

	// Verify state.
	if result.State != state {
		return nil, fmt.Errorf("state mismatch: possible CSRF attack")
	}

	// Exchange code for tokens.
	tokenResp, err := ExchangeCode(ctx, provider, cfg.ClientID, cfg.ClientSecret, result.Code, redirectURI, pkce)
	if err != nil {
		return nil, err
	}

	// Build stored token.
	storedToken := &StoredToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Issuer:       cfg.IssuerURL,
		ClientID:     cfg.ClientID,
	}

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
