package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/keychain"
	"github.com/qjoly/talosctl-oidc/pkg/oidc"
	"github.com/qjoly/talosctl-oidc/pkg/server"
	"github.com/qjoly/talosctl-oidc/pkg/talosconfig"
)

var loginFlags struct {
	provider     string
	clientID     string
	clientSecret string
	scopes       []string
	callbackPort int
	serverURL    string
	contextName  string
	talosconfig  string
	serverCA     string
	insecure     bool
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate via OIDC and obtain ephemeral Talos credentials",
	Long: `Authenticate via an OIDC provider using the Authorization Code flow with PKCE.
Upon successful authentication, the ID token is exchanged with the cert exchange
server for an ephemeral short-lived Talos client certificate, which is written
to the talosconfig file.

When the certificate expires, you must re-authenticate via OIDC.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginFlags.provider, "provider", "", "OIDC issuer URL (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientID, "client-id", "", "OIDC client ID (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientSecret, "client-secret", "", "OIDC client secret (optional, for confidential clients)")
	loginCmd.Flags().StringSliceVar(&loginFlags.scopes, "scopes", []string{"openid", "profile", "email"}, "OIDC scopes")
	loginCmd.Flags().IntVar(&loginFlags.callbackPort, "callback-port", 8900, "Local callback server port")
	loginCmd.Flags().StringVar(&loginFlags.serverURL, "server", "", "Cert exchange server URL (required, e.g. https://localhost:8443)")
	loginCmd.Flags().StringVar(&loginFlags.contextName, "context-name", "oidc", "Name for the talosconfig context")
	loginCmd.Flags().StringVar(&loginFlags.talosconfig, "talosconfig", "", "Path to talosconfig file (default: ~/.talos/config)")
	loginCmd.Flags().StringVar(&loginFlags.serverCA, "server-ca", "", "Path to PEM CA certificate to trust for the cert exchange server (for self-signed TLS)")
	loginCmd.Flags().BoolVar(&loginFlags.insecure, "insecure", false, "Allow plain HTTP connection to the cert exchange server (skip TLS verification)")

	loginCmd.MarkFlagRequired("provider")
	loginCmd.MarkFlagRequired("client-id")
	loginCmd.MarkFlagRequired("server")

	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	talosconfigPath := loginFlags.talosconfig
	if talosconfigPath == "" {
		talosconfigPath = talosconfig.DefaultPath()
	}

	// Validate TLS configuration.
	serverURL := loginFlags.serverURL
	if strings.HasPrefix(serverURL, "http://") && !loginFlags.insecure {
		return fmt.Errorf("plain HTTP server URL requires --insecure flag; use --insecure or switch to https://")
	}

	// Step 1: Authenticate via OIDC to get an ID token.
	idToken, err := obtainIDToken(ctx)
	if err != nil {
		return err
	}

	// Step 2: Exchange the ID token with the cert exchange server for ephemeral certs.
	fmt.Printf("Exchanging token with cert server at %s...\n", serverURL)

	httpClient, err := buildHTTPClient()
	if err != nil {
		return fmt.Errorf("building HTTP client: %w", err)
	}

	certResp, err := exchangeTokenForCert(ctx, httpClient, serverURL, idToken)
	if err != nil {
		return fmt.Errorf("cert exchange failed: %w", err)
	}

	fmt.Printf("Received ephemeral certificate (TTL: %ds)\n", certResp.TTL)

	// Step 3: Write the ephemeral certs to talosconfig.
	cfg, err := talosconfig.Load(talosconfigPath)
	if err != nil {
		return fmt.Errorf("loading talosconfig: %w", err)
	}

	if err := talosconfig.SetContextFromPEM(
		cfg,
		loginFlags.contextName,
		certResp.Endpoints,
		[]byte(certResp.CA),
		[]byte(certResp.Cert),
		[]byte(certResp.Key),
	); err != nil {
		return fmt.Errorf("setting talosconfig context: %w", err)
	}

	if err := talosconfig.Save(talosconfigPath, cfg); err != nil {
		return fmt.Errorf("saving talosconfig: %w", err)
	}

	fmt.Printf("Talosconfig updated: context %q set with endpoints %v\n", loginFlags.contextName, certResp.Endpoints)
	fmt.Printf("Config written to: %s\n", talosconfigPath)
	fmt.Printf("Certificate expires in %s\n", time.Duration(certResp.TTL)*time.Second)

	return nil
}

// buildHTTPClient creates an HTTP client with the appropriate TLS configuration.
//   - If --server-ca is set, the client trusts only that CA for the server connection.
//   - If --insecure is set, TLS verification is disabled entirely.
//   - Otherwise, the system certificate pool is used.
func buildHTTPClient() (*http.Client, error) {
	if loginFlags.insecure {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // user explicitly opted in
				},
			},
			Timeout: 30 * time.Second,
		}, nil
	}

	if loginFlags.serverCA != "" {
		caPEM, err := os.ReadFile(loginFlags.serverCA)
		if err != nil {
			return nil, fmt.Errorf("reading server CA file %s: %w", loginFlags.serverCA, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", loginFlags.serverCA)
		}

		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
			Timeout: 30 * time.Second,
		}, nil
	}

	// Default: use system certs.
	return &http.Client{
		Timeout: 30 * time.Second,
	}, nil
}

// obtainIDToken performs the OIDC flow (or uses cached token) and returns the ID token string.
func obtainIDToken(ctx context.Context) (string, error) {
	// Check for cached token in keychain.
	storedToken, err := keychain.Retrieve(loginFlags.contextName)
	if err != nil {
		fmt.Printf("Warning: could not check keychain: %v\n", err)
	}

	// If we have a valid cached token with an ID token, use it.
	if storedToken != nil && !storedToken.IsExpired() && storedToken.IDToken != "" {
		fmt.Println("Using cached OIDC token (still valid).")
		return storedToken.IDToken, nil
	}

	// Try to refresh if we have a refresh token.
	if storedToken != nil && storedToken.HasRefreshToken() {
		fmt.Println("Token expired, attempting refresh...")

		provider, err := oidc.Discover(ctx, storedToken.Issuer)
		if err != nil {
			fmt.Printf("Discovery failed during refresh: %v\nFalling back to full authentication.\n", err)
		} else {
			tokenResp, err := oidc.RefreshAccessToken(ctx, provider, storedToken.ClientID, loginFlags.clientSecret, storedToken.RefreshToken)
			if err != nil {
				fmt.Printf("Token refresh failed: %v\nFalling back to full authentication.\n", err)
			} else {
				refreshedToken := &oidc.StoredToken{
					AccessToken:  tokenResp.AccessToken,
					RefreshToken: tokenResp.RefreshToken,
					IDToken:      tokenResp.IDToken,
					ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
					Issuer:       storedToken.Issuer,
					ClientID:     storedToken.ClientID,
				}
				if refreshedToken.RefreshToken == "" {
					refreshedToken.RefreshToken = storedToken.RefreshToken
				}

				if err := keychain.Store(loginFlags.contextName, refreshedToken); err != nil {
					fmt.Printf("Warning: could not cache refreshed token: %v\n", err)
				}
				fmt.Println("Token refreshed successfully.")

				if refreshedToken.IDToken != "" {
					return refreshedToken.IDToken, nil
				}
				// If refresh didn't return an ID token, fall through to full auth.
				fmt.Println("Refreshed token has no ID token, performing full authentication...")
			}
		}
	}

	// Full authentication flow.
	fmt.Printf("Authenticating with OIDC provider: %s\n", loginFlags.provider)

	authCfg := oidc.AuthConfig{
		IssuerURL:    loginFlags.provider,
		ClientID:     loginFlags.clientID,
		ClientSecret: loginFlags.clientSecret,
		Scopes:       loginFlags.scopes,
		CallbackPort: loginFlags.callbackPort,
		OpenBrowser:  openBrowser,
	}

	storedToken, err = oidc.Authenticate(ctx, authCfg)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	if err := keychain.Store(loginFlags.contextName, storedToken); err != nil {
		fmt.Printf("Warning: could not cache token in keychain: %v\n", err)
	}

	fmt.Println("Authentication successful.")

	if storedToken.IDToken == "" {
		return "", fmt.Errorf("OIDC provider did not return an ID token; ensure 'openid' scope is requested")
	}

	return storedToken.IDToken, nil
}

// exchangeTokenForCert sends the ID token to the cert exchange server and returns the certificate response.
func exchangeTokenForCert(ctx context.Context, client *http.Client, serverURL, idToken string) (*server.CertResponse, error) {
	exchangeURL := serverURL + "/exchange"

	reqBody, err := json.Marshal(map[string]string{
		"id_token": idToken,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling exchange request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting cert exchange server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp server.ErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var certResp server.CertResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("decoding exchange response: %w", err)
	}

	return &certResp, nil
}

func openBrowser(url string) error {
	fmt.Printf("Opening browser for authentication...\n")
	fmt.Printf("If the browser does not open, visit:\n  %s\n\n", url)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}

	return cmd.Start()
}
