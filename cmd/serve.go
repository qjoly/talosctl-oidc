package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/certsign"
	"github.com/qjoly/talosctl-oidc/pkg/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the cert exchange server",
	Long: `Start the certificate exchange server that validates OIDC tokens
and issues ephemeral Talos client certificates.

All configuration is done via environment variables:

  TALOSCTL_OIDC_CA_CERT        Path to Talos CA certificate (required)
  TALOSCTL_OIDC_CA_KEY         Path to Talos CA private key (required)
  TALOSCTL_OIDC_ISSUER_URL     OIDC issuer URL for token validation (required)
  TALOSCTL_OIDC_CLIENT_ID      Expected OIDC client ID / audience (required)
  TALOSCTL_OIDC_ENDPOINTS      Talos node endpoints, comma-separated (required)
  TALOSCTL_OIDC_CLIENT_SECRET  OIDC client secret (for HS256-signed tokens)
  TALOSCTL_OIDC_LISTEN         Address to listen on (default: ":8443")
  TALOSCTL_OIDC_CERT_TTL       Certificate lifetime (default: "1h")
  TALOSCTL_OIDC_ROLES          Talos roles, comma-separated (default: "os:admin")

TLS configuration:

  TALOSCTL_OIDC_TLS_CERT       Path to TLS certificate file
  TALOSCTL_OIDC_TLS_KEY        Path to TLS private key file
  TALOSCTL_OIDC_INSECURE       Set to "true" to serve plain HTTP (no TLS)
  TALOSCTL_OIDC_DATA_DIR       Directory to persist the self-signed TLS certificate

By default (no TLS env vars set), the server generates a self-signed TLS
certificate at startup and logs the CA PEM so clients can trust it via
the --server-ca flag on the login command.

When TALOSCTL_OIDC_DATA_DIR is set, the self-signed certificate is persisted
to that directory and reused across restarts (the CA PEM stays stable).

TLS modes (in order of precedence):
  1. TALOSCTL_OIDC_TLS_CERT + TALOSCTL_OIDC_TLS_KEY  -> HTTPS with provided certs
  2. TALOSCTL_OIDC_INSECURE=true                      -> plain HTTP (WARNING: insecure)
  3. Default                                           -> HTTPS with auto-generated self-signed cert`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Read all configuration from environment variables.
	caCert := os.Getenv("TALOSCTL_OIDC_CA_CERT")
	caKey := os.Getenv("TALOSCTL_OIDC_CA_KEY")
	issuerURL := os.Getenv("TALOSCTL_OIDC_ISSUER_URL")
	clientID := os.Getenv("TALOSCTL_OIDC_CLIENT_ID")
	endpointsRaw := os.Getenv("TALOSCTL_OIDC_ENDPOINTS")
	clientSecret := os.Getenv("TALOSCTL_OIDC_CLIENT_SECRET")
	listen := os.Getenv("TALOSCTL_OIDC_LISTEN")
	certTTLRaw := os.Getenv("TALOSCTL_OIDC_CERT_TTL")
	rolesRaw := os.Getenv("TALOSCTL_OIDC_ROLES")

	// TLS env vars.
	tlsCert := os.Getenv("TALOSCTL_OIDC_TLS_CERT")
	tlsKey := os.Getenv("TALOSCTL_OIDC_TLS_KEY")
	insecureRaw := os.Getenv("TALOSCTL_OIDC_INSECURE")
	dataDir := os.Getenv("TALOSCTL_OIDC_DATA_DIR")

	// Validate required env vars.
	var missing []string
	if caCert == "" {
		missing = append(missing, "TALOSCTL_OIDC_CA_CERT")
	}
	if caKey == "" {
		missing = append(missing, "TALOSCTL_OIDC_CA_KEY")
	}
	if issuerURL == "" {
		missing = append(missing, "TALOSCTL_OIDC_ISSUER_URL")
	}
	if clientID == "" {
		missing = append(missing, "TALOSCTL_OIDC_CLIENT_ID")
	}
	if endpointsRaw == "" {
		missing = append(missing, "TALOSCTL_OIDC_ENDPOINTS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required environment variables not set: %s", strings.Join(missing, ", "))
	}

	// Apply defaults.
	if listen == "" {
		listen = ":8443"
	}

	certTTL := 1 * time.Hour
	if certTTLRaw != "" {
		d, err := time.ParseDuration(certTTLRaw)
		if err != nil {
			return fmt.Errorf("invalid TALOSCTL_OIDC_CERT_TTL %q: %w", certTTLRaw, err)
		}
		certTTL = d
	}

	roles := []string{"os:admin"}
	if rolesRaw != "" {
		roles = strings.Split(rolesRaw, ",")
	}

	endpoints := strings.Split(endpointsRaw, ",")

	insecure := strings.EqualFold(insecureRaw, "true") || insecureRaw == "1"

	// Validate TLS configuration.
	if (tlsCert != "") != (tlsKey != "") {
		return fmt.Errorf("TALOSCTL_OIDC_TLS_CERT and TALOSCTL_OIDC_TLS_KEY must both be set (or both unset)")
	}
	if tlsCert != "" && insecure {
		return fmt.Errorf("cannot set both TALOSCTL_OIDC_TLS_CERT and TALOSCTL_OIDC_INSECURE=true")
	}

	// Load the Talos CA.
	ca, err := certsign.LoadCA(caCert, caKey)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}

	log.Printf("Loaded Talos CA from %s", caCert)

	cfg := server.Config{
		ListenAddr:   listen,
		CA:           ca,
		CertTTL:      certTTL,
		Roles:        roles,
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoints:    endpoints,
		TLSCertFile:  tlsCert,
		TLSKeyFile:   tlsKey,
		Insecure:     insecure,
		DataDir:      dataDir,
	}

	srv := server.New(cfg)

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s, shutting down...", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown error: %w", err)
		}
		log.Println("Server stopped gracefully.")
		return nil
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}
