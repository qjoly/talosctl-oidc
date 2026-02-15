package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/keychain"
	"github.com/qjoly/talosctl-oidc/pkg/oidc"
	"github.com/qjoly/talosctl-oidc/pkg/talosconfig"
)

var loginFlags struct {
	provider     string
	clientID     string
	clientSecret string
	scopes       []string
	callbackPort int
	caCert       string
	clientCert   string
	clientKey    string
	endpoints    []string
	contextName  string
	talosconfig  string
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate via OIDC and write credentials to talosconfig",
	Long: `Authenticate via an OIDC provider using the Authorization Code flow with PKCE.
Upon successful authentication, pre-provisioned Talos admin client certificates
are written to the talosconfig file.`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginFlags.provider, "provider", "", "OIDC issuer URL (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientID, "client-id", "", "OIDC client ID (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientSecret, "client-secret", "", "OIDC client secret (optional, for confidential clients)")
	loginCmd.Flags().StringSliceVar(&loginFlags.scopes, "scopes", []string{"openid", "profile", "email"}, "OIDC scopes")
	loginCmd.Flags().IntVar(&loginFlags.callbackPort, "callback-port", 8900, "Local callback server port")
	loginCmd.Flags().StringVar(&loginFlags.caCert, "ca-cert", "", "Path to Talos CA certificate (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientCert, "client-cert", "", "Path to pre-provisioned client certificate (required)")
	loginCmd.Flags().StringVar(&loginFlags.clientKey, "client-key", "", "Path to pre-provisioned client key (required)")
	loginCmd.Flags().StringSliceVar(&loginFlags.endpoints, "endpoints", nil, "Talos node endpoints (required)")
	loginCmd.Flags().StringVar(&loginFlags.contextName, "context-name", "oidc", "Name for the talosconfig context")
	loginCmd.Flags().StringVar(&loginFlags.talosconfig, "talosconfig", "", "Path to talosconfig file (default: ~/.talos/config)")

	loginCmd.MarkFlagRequired("provider")
	loginCmd.MarkFlagRequired("client-id")
	loginCmd.MarkFlagRequired("ca-cert")
	loginCmd.MarkFlagRequired("client-cert")
	loginCmd.MarkFlagRequired("client-key")
	loginCmd.MarkFlagRequired("endpoints")

	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	talosconfigPath := loginFlags.talosconfig
	if talosconfigPath == "" {
		talosconfigPath = talosconfig.DefaultPath()
	}

	// Check for cached token in keychain.
	storedToken, err := keychain.Retrieve(loginFlags.contextName)
	if err != nil {
		fmt.Printf("Warning: could not check keychain: %v\n", err)
	}

	needsAuth := true

	if storedToken != nil && !storedToken.IsExpired() {
		fmt.Println("Using cached OIDC token (still valid).")
		needsAuth = false
	} else if storedToken != nil && storedToken.HasRefreshToken() {
		fmt.Println("Token expired, attempting refresh...")

		provider, err := oidc.Discover(ctx, storedToken.Issuer)
		if err != nil {
			fmt.Printf("Discovery failed during refresh: %v\nFalling back to full authentication.\n", err)
		} else {
			tokenResp, err := oidc.RefreshAccessToken(ctx, provider, storedToken.ClientID, loginFlags.clientSecret, storedToken.RefreshToken)
			if err != nil {
				fmt.Printf("Token refresh failed: %v\nFalling back to full authentication.\n", err)
			} else {
				storedToken = &oidc.StoredToken{
					AccessToken:  tokenResp.AccessToken,
					RefreshToken: tokenResp.RefreshToken,
					IDToken:      tokenResp.IDToken,
					ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
					Issuer:       storedToken.Issuer,
					ClientID:     storedToken.ClientID,
				}
				// Keep existing refresh token if the provider didn't rotate it.
				if storedToken.RefreshToken == "" {
					storedToken.RefreshToken = tokenResp.RefreshToken
				}

				if err := keychain.Store(loginFlags.contextName, storedToken); err != nil {
					fmt.Printf("Warning: could not cache refreshed token: %v\n", err)
				}
				fmt.Println("Token refreshed successfully.")
				needsAuth = false
			}
		}
	}

	if needsAuth {
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
			return fmt.Errorf("authentication failed: %w", err)
		}

		if err := keychain.Store(loginFlags.contextName, storedToken); err != nil {
			fmt.Printf("Warning: could not cache token in keychain: %v\n", err)
		}

		fmt.Println("Authentication successful.")
	}

	// Write certs to talosconfig.
	cfg, err := talosconfig.Load(talosconfigPath)
	if err != nil {
		return fmt.Errorf("loading talosconfig: %w", err)
	}

	if err := talosconfig.SetContext(cfg, loginFlags.contextName, loginFlags.endpoints, loginFlags.caCert, loginFlags.clientCert, loginFlags.clientKey); err != nil {
		return fmt.Errorf("setting talosconfig context: %w", err)
	}

	if err := talosconfig.Save(talosconfigPath, cfg); err != nil {
		return fmt.Errorf("saving talosconfig: %w", err)
	}

	fmt.Printf("Talosconfig updated: context %q set with endpoints %s\n", loginFlags.contextName, strings.Join(loginFlags.endpoints, ", "))
	fmt.Printf("Config written to: %s\n", talosconfigPath)

	return nil
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
