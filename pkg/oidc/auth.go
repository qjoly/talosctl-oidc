package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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
	addrs       []string
	redirectURI string
	useTLS      bool
	server      *http.Server
	listeners   []net.Listener
	resultCh    chan AuthResult
	errCh       chan error
}

// NewCallbackServer listens on every "host:port" in cfg.ListenAddresses and
// serves the callback on all of them, so a dual-stack host can be reached over
// v4 and v6. The redirect URI is derived from the first address, unless
// cfg.RedirectURL overrides it; a cert/key pair makes the listeners speak TLS.
func NewCallbackServer(cfg AuthConfig) (*CallbackServer, error) {
	if len(cfg.ListenAddresses) == 0 {
		return nil, fmt.Errorf("no callback listen address configured")
	}

	tlsConfig, err := cfg.callbackTLSConfig()
	if err != nil {
		return nil, err
	}

	cs := &CallbackServer{
		addrs:    cfg.ListenAddresses,
		useTLS:   tlsConfig != nil,
		resultCh: make(chan AuthResult, 1),
		errCh:    make(chan error, len(cfg.ListenAddresses)+1),
	}

	scheme := "http"
	if cs.useTLS {
		scheme = "https"
	}
	cs.redirectURI = fmt.Sprintf("%s://%s/callback", scheme, cfg.ListenAddresses[0])

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", cs.handleCallback)
	mux.HandleFunc("/logo", handleLogo)

	if cfg.RedirectURL != "" {
		u, err := url.Parse(cfg.RedirectURL)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect URL %q: %w", cfg.RedirectURL, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("redirect URL %q must be absolute, e.g. https://talos.example.com:8900/callback", cfg.RedirectURL)
		}
		// The provider sends the browser to that exact path, so answer on it too.
		if u.Path != "" && u.Path != "/" && u.Path != "/callback" {
			mux.HandleFunc(u.Path, cs.handleCallback)
		}
		cs.redirectURI = cfg.RedirectURL
	}

	for _, addr := range cfg.ListenAddresses {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			cs.closeListeners()
			return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		cs.listeners = append(cs.listeners, listener)
	}

	cs.server = &http.Server{
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return cs, nil
}

func (cs *CallbackServer) closeListeners() {
	for _, l := range cs.listeners {
		l.Close()
	}
}

// RedirectURI returns the callback URL advertised to the OIDC provider.
func (cs *CallbackServer) RedirectURI() string {
	return cs.redirectURI
}

// Start begins serving on every listener in the background.
func (cs *CallbackServer) Start() {
	for _, l := range cs.listeners {
		go func() {
			var err error
			if cs.useTLS {
				// The key pair already lives in server.TLSConfig.
				err = cs.server.ServeTLS(l, "", "")
			} else {
				err = cs.server.Serve(l)
			}
			if err != nil && err != http.ErrServerClosed {
				cs.errCh <- err
			}
		}()
	}
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
	callbackServer, err := NewCallbackServer(cfg)
	if err != nil {
		return nil, err
	}
	callbackServer.Start()
	debug("Callback server started on %v", cfg.ListenAddresses)
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
	scopes := cfg.scopesOrDefault()
	authURL := BuildAuthorizationURL(provider, cfg.ClientID, redirectURI, scopes, state, pkce)
	debug("Full authorization URL: %s", authURL)

	// Open browser. The URL has already been printed at this point and the
	// callback server is listening, so a failure here is not fatal: the user can
	// still open it by hand.
	if cfg.OpenBrowser != nil {
		if err := cfg.OpenBrowser(authURL); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open a browser (%v). Open the URL above manually.\n", err)
		}
	}

	fmt.Println("Waiting for authentication callback...")

	// Wait for the callback.
	result, err := callbackServer.WaitForCallback(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	debug("OIDC callback received successfully")

	// Verify state using constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(result.State), []byte(state)) != 1 {
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

	return newStoredToken(tokenResp, cfg), nil
}

// AuthenticateDevice performs the OAuth 2.0 device authorization grant (RFC 8628):
// it prints a URL and a user code to enter on another device, then polls the token
// endpoint until the login is approved. No browser and no callback server involved.
func AuthenticateDevice(ctx context.Context, cfg AuthConfig) (*StoredToken, error) {
	debug("Starting device authorization flow for issuer: %s", cfg.IssuerURL)

	provider, err := Discover(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	auth, err := RequestDeviceCode(ctx, provider, cfg.ClientID, cfg.ClientSecret, cfg.scopesOrDefault())
	if err != nil {
		return nil, err
	}

	if auth.VerificationURIComplete != "" {
		fmt.Printf("Open this URL on any device to authenticate:\n  %s\n\n", auth.VerificationURIComplete)
		fmt.Printf("If it asks for a code, enter: %s\n\n", auth.UserCode)
	} else {
		fmt.Printf("Open %s on any device and enter the code: %s\n\n", auth.VerificationURI, auth.UserCode)
	}
	fmt.Println("Waiting for the login to be approved...")

	tokenResp, err := PollDeviceToken(ctx, provider, cfg.ClientID, cfg.ClientSecret, auth)
	if err != nil {
		return nil, fmt.Errorf("device authentication failed: %w", err)
	}

	return newStoredToken(tokenResp, cfg), nil
}

// newStoredToken turns a token endpoint response into what we persist.
func newStoredToken(tokenResp *TokenResponse, cfg AuthConfig) *StoredToken {
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

	return storedToken
}

// AuthConfig holds configuration for the OIDC authentication flow.
type AuthConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// ListenAddresses are the "host:port" the callback server binds to; the
	// first one is used as the redirect URI.
	ListenAddresses []string
	// RedirectURL overrides the redirect URI sent to the provider, for providers
	// that reject loopback or plain-HTTP callbacks.
	RedirectURL string
	// TLSCertFile and TLSKeyFile make the callback server serve HTTPS.
	TLSCertFile string
	TLSKeyFile  string
	OpenBrowser func(url string) error
}

// callbackTLSConfig returns nil when the callback server should stay on plain HTTP.
func (cfg AuthConfig) callbackTLSConfig() (*tls.Config, error) {
	if cfg.TLSCertFile == "" && cfg.TLSKeyFile == "" {
		return nil, nil
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("serving the callback over TLS needs both a certificate and a key")
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading callback TLS key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (cfg AuthConfig) scopesOrDefault() []string {
	if len(cfg.Scopes) == 0 {
		return []string{"openid", "profile", "email", "offline_access"}
	}
	return cfg.Scopes
}
