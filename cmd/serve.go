package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/admin"
	"github.com/qjoly/talosctl-oidc/pkg/audit"
	"github.com/qjoly/talosctl-oidc/pkg/certsign"
	"github.com/qjoly/talosctl-oidc/pkg/config"
	"github.com/qjoly/talosctl-oidc/pkg/server"
)

var serveFlags struct {
	configFile string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the cert exchange server",
	Long: `Start the certificate exchange server that validates OIDC tokens
and issues ephemeral Talos client certificates.

Configuration is loaded from a YAML file and/or environment variables.
When both are provided, environment variables take precedence over the
config file (allowing the file to set base values and env vars to override).

Configuration file:

  --config / TALOSCTL_OIDC_CONFIG    Path to YAML configuration file

Example configuration file:

  issuer_url: https://accounts.google.com
  client_id: my-client-id
  endpoints:
    - 10.0.0.1
    - 10.0.0.2
  ca_cert: /path/to/ca.crt
  ca_key: /path/to/ca.key
  listen: ":8443"
  cert_ttl: "1h"
  roles:
    - os:admin
  tls_cert: /path/to/tls.crt
  tls_key: /path/to/tls.key
  data_dir: /var/lib/talosctl-oidc
  audit_log: /var/log/talosctl-oidc/audit.log
  admin_token: my-secret-token

Environment variables (override config file values):

  TALOSCTL_OIDC_CONFIG       Path to YAML configuration file (alternative to --config)
  TALOSCTL_OIDC_CA_CERT      Path to Talos CA certificate file
  TALOSCTL_OIDC_CA_KEY       Path to Talos CA private key file
  TALOSCTL_OIDC_CA_CERT_DATA PEM-encoded Talos CA certificate, inline
  TALOSCTL_OIDC_CA_KEY_DATA  PEM-encoded Talos CA private key, inline
  TALOSCTL_OIDC_TALOS_CONFIG Path to a talosconfig YAML file
  TALOSCTL_OIDC_ISSUER_URL   OIDC issuer URL for token validation
  TALOSCTL_OIDC_CLIENT_ID    Expected OIDC client ID / audience
  TALOSCTL_OIDC_ENDPOINTS    Talos node endpoints, comma-separated
  TALOSCTL_OIDC_CLIENT_SECRET OIDC client secret (for HS256-signed tokens)
  TALOSCTL_OIDC_LISTEN       Address to listen on (default: ":8443")
  TALOSCTL_OIDC_CERT_TTL     Certificate lifetime (default: "1h")
  TALOSCTL_OIDC_ROLES        Talos roles, comma-separated (default: "os:admin")

TLS configuration:

  TALOSCTL_OIDC_TLS_CERT     Path to TLS certificate file
  TALOSCTL_OIDC_TLS_KEY      Path to TLS private key file
  TALOSCTL_OIDC_INSECURE     Set to "true" to serve plain HTTP (no TLS)
  TALOSCTL_OIDC_DATA_DIR     Directory to persist the self-signed TLS certificate

Audit & admin:

  TALOSCTL_OIDC_AUDIT_LOG    Path to audit log file (default: stdout, "-" for stdout)
  TALOSCTL_OIDC_ADMIN_TOKEN  Bearer token for /admin/* endpoints

By default (no TLS config), the server generates a self-signed TLS
certificate at startup and logs the CA PEM so clients can trust it via
the --server-ca flag on the login command.

TLS modes (in order of precedence):
  1. tls_cert + tls_key (or env vars)  -> HTTPS with provided certs
  2. insecure=true (or env var)        -> plain HTTP (WARNING: insecure)
  3. Default                           -> HTTPS with auto-generated self-signed cert`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVarP(&serveFlags.configFile, "config", "c", "", "path to YAML configuration file (env: TALOSCTL_OIDC_CONFIG)")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Load configuration from file + environment variables.
	rc, err := config.Load(serveFlags.configFile)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Apply defaults for optional fields.
	rc.ApplyDefaults()

	// Validate required configuration.
	if err := rc.Validate(); err != nil {
		return err
	}

	// Parse the certificate TTL.
	certTTL, err := rc.ParseCertTTL()
	if err != nil {
		return err
	}

	// Log configuration source.
	if serveFlags.configFile != "" {
		log.Printf("Configuration loaded from file: %s (env vars override)", serveFlags.configFile)
	} else if os.Getenv("TALOSCTL_OIDC_CONFIG") != "" {
		log.Printf("Configuration loaded from file: %s (env vars override)", os.Getenv("TALOSCTL_OIDC_CONFIG"))
	} else {
		log.Printf("Configuration loaded from environment variables")
	}

	// Load the Talos CA.
	// Priority order:
	//   1. talos_config — talosconfig YAML file (e.g. from talos.dev ServiceAccount)
	//   2. ca_cert_data / ca_key_data — inline PEM
	//   3. ca_cert / ca_key — file paths
	var ca *certsign.CA
	var caErr error
	if rc.TalosConfig != "" {
		ca, caErr = certsign.LoadCAFromTalosConfig(rc.TalosConfig)
		if caErr != nil {
			return fmt.Errorf("loading CA from talosconfig %s: %w", rc.TalosConfig, caErr)
		}
		log.Printf("Loaded Talos CA from talosconfig %s", rc.TalosConfig)
	} else if rc.CACertData != "" && rc.CAKeyData != "" {
		ca, caErr = certsign.ParseCA([]byte(rc.CACertData), []byte(rc.CAKeyData))
		if caErr != nil {
			return fmt.Errorf("loading CA from inline data: %w", caErr)
		}
		log.Printf("Loaded Talos CA from inline data (ca_cert_data)")
	} else {
		ca, caErr = certsign.LoadCA(rc.CACert, rc.CAKey)
		if caErr != nil {
			return fmt.Errorf("loading CA: %w", caErr)
		}
		log.Printf("Loaded Talos CA from %s", rc.CACert)
	}

	// Initialize the audit logger.
	auditLogger, err := audit.NewLogger(rc.AuditLog)
	if err != nil {
		return fmt.Errorf("initializing audit logger: %w", err)
	}
	defer auditLogger.Close()

	if rc.AuditLog != "" && rc.AuditLog != "-" {
		log.Printf("Audit log: %s", rc.AuditLog)
	} else {
		log.Printf("Audit log: stdout")
	}

	// Initialize admin tracker (subscribes to audit events).
	tracker := admin.NewTracker(auditLogger)

	if rc.AdminToken != "" {
		log.Printf("Admin API: enabled (protected by bearer token)")
	} else {
		log.Printf("Admin API: disabled (set admin_token / TALOSCTL_OIDC_ADMIN_TOKEN to enable)")
	}

	cfg := server.Config{
		ListenAddr:   rc.Listen,
		CA:           ca,
		CertTTL:      certTTL,
		Roles:        rc.Roles,
		IssuerURL:    rc.IssuerURL,
		ClientID:     rc.ClientID,
		ClientSecret: rc.ClientSecret,
		Endpoints:    rc.Endpoints,
		TLSCertFile:  rc.TLSCert,
		TLSKeyFile:   rc.TLSKey,
		Insecure:     rc.Insecure,
		DataDir:      rc.DataDir,
		AuditLogger:  auditLogger,
		AdminToken:   rc.AdminToken,
		AdminTracker: tracker,
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
