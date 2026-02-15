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

var serveFlags struct {
	caCert       string
	caKey        string
	listen       string
	certTTL      time.Duration
	issuerURL    string
	clientID     string
	clientSecret string
	endpoints    []string
	roles        []string
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the cert exchange server",
	Long: `Start the certificate exchange server that validates OIDC tokens
and issues ephemeral Talos client certificates.

The server holds the Talos CA private key and signs short-lived client
certificates for users who present a valid OIDC ID token.

Users authenticate via the 'login' command which performs the OIDC flow,
then exchanges the ID token with this server for an ephemeral certificate.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveFlags.caCert, "ca-cert", "", "Path to Talos CA certificate (required)")
	serveCmd.Flags().StringVar(&serveFlags.caKey, "ca-key", "", "Path to Talos CA private key (required)")
	serveCmd.Flags().StringVar(&serveFlags.listen, "listen", ":8443", "Address to listen on")
	serveCmd.Flags().DurationVar(&serveFlags.certTTL, "cert-ttl", 1*time.Hour, "Lifetime of issued client certificates")
	serveCmd.Flags().StringVar(&serveFlags.issuerURL, "issuer-url", "", "OIDC issuer URL for token validation (required)")
	serveCmd.Flags().StringVar(&serveFlags.clientID, "client-id", "", "Expected OIDC client ID / audience (required)")
	serveCmd.Flags().StringVar(&serveFlags.clientSecret, "client-secret", "", "OIDC client secret (required for HS256-signed tokens)")
	serveCmd.Flags().StringSliceVar(&serveFlags.endpoints, "endpoints", nil, "Talos node endpoints to include in responses (required)")
	serveCmd.Flags().StringSliceVar(&serveFlags.roles, "roles", []string{"os:admin"}, "Talos roles to assign to issued certificates")

	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	// Resolve flags from environment variables when not set via CLI.
	resolveServeEnv(cmd)

	// Validate required flags (they may have been set via env vars after flag parsing).
	for _, name := range []string{"ca-cert", "ca-key", "issuer-url", "client-id", "endpoints"} {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			continue
		}
		if f.Value.String() == "" || f.Value.String() == "[]" {
			return fmt.Errorf("required flag %q not set (set via --%s or env var)", name, name)
		}
	}

	// Load the Talos CA.
	ca, err := certsign.LoadCA(serveFlags.caCert, serveFlags.caKey)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}

	log.Printf("Loaded Talos CA from %s", serveFlags.caCert)

	cfg := server.Config{
		ListenAddr:   serveFlags.listen,
		CA:           ca,
		CertTTL:      serveFlags.certTTL,
		Roles:        serveFlags.roles,
		IssuerURL:    serveFlags.issuerURL,
		ClientID:     serveFlags.clientID,
		ClientSecret: serveFlags.clientSecret,
		Endpoints:    serveFlags.endpoints,
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

// resolveServeEnv sets serve flags from environment variables when the flag
// was not explicitly provided on the command line. This allows the extension
// to be configured via ExtensionServiceConfig environment variables.
//
// Environment variables:
//
//	TALOSCTL_OIDC_CA_CERT      -> --ca-cert
//	TALOSCTL_OIDC_CA_KEY       -> --ca-key
//	TALOSCTL_OIDC_LISTEN       -> --listen
//	TALOSCTL_OIDC_CERT_TTL     -> --cert-ttl
//	TALOSCTL_OIDC_ISSUER_URL   -> --issuer-url
//	TALOSCTL_OIDC_CLIENT_ID    -> --client-id
//	TALOSCTL_OIDC_CLIENT_SECRET -> --client-secret
//	TALOSCTL_OIDC_ENDPOINTS    -> --endpoints (comma-separated)
//	TALOSCTL_OIDC_ROLES        -> --roles (comma-separated)
func resolveServeEnv(cmd *cobra.Command) {
	envMap := map[string]string{
		"ca-cert":       "TALOSCTL_OIDC_CA_CERT",
		"ca-key":        "TALOSCTL_OIDC_CA_KEY",
		"listen":        "TALOSCTL_OIDC_LISTEN",
		"issuer-url":    "TALOSCTL_OIDC_ISSUER_URL",
		"client-id":     "TALOSCTL_OIDC_CLIENT_ID",
		"client-secret": "TALOSCTL_OIDC_CLIENT_SECRET",
	}

	for flagName, envName := range envMap {
		if !cmd.Flags().Changed(flagName) {
			if v := os.Getenv(envName); v != "" {
				cmd.Flags().Set(flagName, v)
			}
		}
	}

	// Duration flag.
	if !cmd.Flags().Changed("cert-ttl") {
		if v := os.Getenv("TALOSCTL_OIDC_CERT_TTL"); v != "" {
			cmd.Flags().Set("cert-ttl", v)
		}
	}

	// Slice flags (comma-separated env values).
	if !cmd.Flags().Changed("endpoints") {
		if v := os.Getenv("TALOSCTL_OIDC_ENDPOINTS"); v != "" {
			serveFlags.endpoints = strings.Split(v, ",")
		}
	}
	if !cmd.Flags().Changed("roles") {
		if v := os.Getenv("TALOSCTL_OIDC_ROLES"); v != "" {
			serveFlags.roles = strings.Split(v, ",")
		}
	}
}
