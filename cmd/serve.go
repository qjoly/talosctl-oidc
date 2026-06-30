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
	"github.com/qjoly/talosctl-oidc/pkg/allowlist"
	"github.com/qjoly/talosctl-oidc/pkg/audit"
	"github.com/qjoly/talosctl-oidc/pkg/config"
	"github.com/qjoly/talosctl-oidc/pkg/ratelimit"
	"github.com/qjoly/talosctl-oidc/pkg/rbac"
	"github.com/qjoly/talosctl-oidc/pkg/server"
	"github.com/qjoly/talosctl-oidc/pkg/talosapi"
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
  # talos_config: /var/run/secrets/talos.dev/config  # empty = in-cluster ServiceAccount
  listen: ":8443"
  cert_ttl: "1h"
  roles:
    - os:admin
  tls_cert: /path/to/tls.crt
  tls_key: /path/to/tls.key
  data_dir: /var/lib/talosctl-oidc
  audit_log: /var/log/talosctl-oidc/audit.log
  admin_token: my-secret-token
  rate_limit_requests: 10
  rate_limit_window: "1m"
  ip_allowlist:
    - 192.168.1.0/24
    - 10.0.0.50

Environment variables (override config file values):

  TALOSCTL_OIDC_CONFIG       Path to YAML configuration file (alternative to --config)
  TALOSCTL_OIDC_TALOS_CONFIG Path to a talosconfig (Talos API client credential; empty = in-cluster ServiceAccount)
  TALOSCTL_OIDC_ISSUER_URL   OIDC issuer URL for token validation
  TALOSCTL_OIDC_CLIENT_ID    Expected OIDC client ID / audience
  TALOSCTL_OIDC_ENDPOINTS    Talos node endpoints, comma-separated
  TALOSCTL_OIDC_CLIENT_SECRET      OIDC client secret (for HS256-signed tokens)
  TALOSCTL_OIDC_CLIENT_SECRET_FILE  Path to file containing OIDC client secret (recommended over flag/env var)
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

Rate limiting:

  TALOSCTL_OIDC_RATE_LIMIT_REQUESTS  Requests per window (default: 0 = disabled)
  TALOSCTL_OIDC_RATE_LIMIT_WINDOW    Rate limit window (default: "1m")

IP allowlist:

  TALOSCTL_OIDC_IP_ALLOWLIST  Comma-separated list of allowed IPs/CIDRs (default: allow all)

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

	// Load client secret from file if configured (avoids exposing in process list).
	if err := rc.LoadClientSecret(); err != nil {
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

	// Build the certificate issuer. Signing is delegated to the Talos API
	// (GenerateClientConfiguration) using a client credential — talos_config, or
	// the in-cluster talos.dev ServiceAccount. The CA private key never reaches
	// this server, and the roles it can grant are bounded by its own credential.
	issuer := talosapi.NewIssuer(rc.TalosConfig, rc.Endpoints)
	if rc.TalosConfig != "" {
		log.Printf("Issuing via Talos API using talosconfig %s", rc.TalosConfig)
	} else {
		log.Printf("Issuing via Talos API using the in-cluster ServiceAccount credential")
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

	// Initialize rate limiter if configured.
	var rateLimiter *ratelimit.Limiter
	if rc.RateLimitRequests > 0 {
		window := rc.RateLimitWindow
		if window <= 0 {
			window = time.Minute
		}
		rateLimiter = ratelimit.New(rc.RateLimitRequests, window, rc.TrustedProxies)
		cleanupStop := rateLimiter.StartCleanup(5 * time.Minute)
		defer close(cleanupStop)
		log.Printf("Rate limiting: enabled (%d requests per %v)", rc.RateLimitRequests, window)
	} else {
		log.Printf("Rate limiting: disabled")
	}

	// Initialize IP allowlist if configured.
	var ipAllowlist *allowlist.Allowlist
	if len(rc.IPAllowlist) > 0 {
		var err error
		ipAllowlist, err = allowlist.New(rc.IPAllowlist, rc.TrustedProxies)
		if err != nil {
			return fmt.Errorf("initializing IP allowlist: %w", err)
		}
		log.Printf("IP allowlist: enabled (%d entries)", len(rc.IPAllowlist))
	} else {
		log.Printf("IP allowlist: disabled")
	}

	// Initialize RBAC mapper if rules are configured.
	var rbacMapper *rbac.Mapper
	if len(rc.RBAC.Rules) > 0 {
		rbacMapper = rbac.NewMapper(rc.RBAC.Rules, rc.Roles)
		log.Printf("RBAC: enabled (%d rules, default roles: %v)", len(rc.RBAC.Rules), rc.Roles)
	} else {
		log.Printf("RBAC: disabled (using static roles: %v)", rc.Roles)
	}

	cfg := server.Config{
		ListenAddr:   rc.Listen,
		Issuer:       issuer,
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
		RateLimiter:  rateLimiter,
		Allowlist:    ipAllowlist,
		RBACMapper:   rbacMapper,
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
