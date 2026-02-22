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

	_ "embed"
)

//go:embed assets/talos-logo.png
var talosLogo []byte

func handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Write(talosLogo)
}

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
	mux.HandleFunc("/logo", handleLogo)

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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Successful - talosctl-oidc</title>
    <style>
        :root {
            --bg-color: #f5f5f5;
            --card-bg: white;
            --text-primary: #1a1a2e;
            --text-secondary: #666;
            --shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        @media (prefers-color-scheme: dark) {
            :root {
                --bg-color: #1a1a2e;
                --card-bg: #2d2d44;
                --text-primary: #f5f5f5;
                --text-secondary: #a0a0a0;
                --shadow: 0 4px 12px rgba(0,0,0,0.3);
            }
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-color);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.3s ease, color 0.3s ease;
        }
        
        .card {
            background: var(--card-bg);
            border-radius: 8px;
            box-shadow: var(--shadow);
            padding: 2.5rem;
            text-align: center;
            max-width: 400px;
            width: 90%;
            transition: background 0.3s ease, box-shadow 0.3s ease;
        }
        
        .icon {
            width: 64px;
            height: 64px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
        }
        
        .icon img {
            width: 48px;
            height: 48px;
        }
        
        h1 {
            color: var(--text-primary);
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        p {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">
            <img src="/logo" alt="Talos" style="width: 48px; height: 48px;">
        </div>
        <h1>Authentication Successful</h1>
        <p>You can now return to your terminal.</p>
    </div>
    <script>
        setTimeout(function() { window.close(); }, 3000);
    </script>
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
