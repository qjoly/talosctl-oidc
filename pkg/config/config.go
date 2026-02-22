// Package config provides configuration loading for the talosctl-oidc server.
//
// Configuration is loaded from two sources, with environment variables taking
// precedence over values defined in a YAML configuration file:
//
//  1. YAML configuration file (base values)
//  2. Environment variables (override file values)
//
// The config file path is resolved in order:
//   - --config flag on the serve command
//   - TALOSCTL_OIDC_CONFIG environment variable
//
// When no config file is specified, all values come from environment variables
// (backwards-compatible with the original behavior).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig represents the YAML configuration file structure.
// All fields are optional; missing fields are left at their zero value and
// can be filled in by environment variables.
type FileConfig struct {
	// CA configuration.
	CACert      string `yaml:"ca_cert"`      // Path to Talos CA certificate file.
	CAKey       string `yaml:"ca_key"`       // Path to Talos CA private key file.
	CACertData  string `yaml:"ca_cert_data"` // PEM-encoded Talos CA certificate, inline.
	CAKeyData   string `yaml:"ca_key_data"`  // PEM-encoded Talos CA private key, inline.
	TalosConfig string `yaml:"talos_config"` // Path to talosconfig YAML file.

	// OIDC configuration.
	IssuerURL    string `yaml:"issuer_url"`    // OIDC issuer URL for token validation.
	ClientID     string `yaml:"client_id"`     // Expected OIDC client ID / audience.
	ClientSecret string `yaml:"client_secret"` // OIDC client secret (for HS256-signed tokens).

	// Server configuration.
	Listen    string   `yaml:"listen"`    // Address to listen on (default: ":8443").
	Endpoints []string `yaml:"endpoints"` // Talos node endpoints.
	CertTTL   string   `yaml:"cert_ttl"`  // Certificate lifetime (e.g. "1h").
	Roles     []string `yaml:"roles"`     // Talos roles (default: ["os:admin"]).

	// TLS configuration.
	TLSCert  string `yaml:"tls_cert"` // Path to TLS certificate file.
	TLSKey   string `yaml:"tls_key"`  // Path to TLS private key file.
	Insecure bool   `yaml:"insecure"` // Serve plain HTTP (no TLS).
	DataDir  string `yaml:"data_dir"` // Directory to persist self-signed TLS certificate.

	// Audit & admin configuration.
	AuditLog   string `yaml:"audit_log"`   // Path to audit log file.
	AdminToken string `yaml:"admin_token"` // Bearer token for /admin/* endpoints.
}

// ResolvedConfig holds the final merged configuration values as strings,
// ready for validation and conversion in the serve command.
type ResolvedConfig struct {
	CACert       string
	CAKey        string
	CACertData   string
	CAKeyData    string
	TalosConfig  string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Listen       string
	Endpoints    []string
	CertTTL      string
	Roles        []string
	TLSCert      string
	TLSKey       string
	Insecure     bool
	DataDir      string
	AuditLog     string
	AdminToken   string
}

// LoadFile reads and parses a YAML configuration file.
// Returns an empty FileConfig (no error) if path is empty.
func LoadFile(path string) (*FileConfig, error) {
	if path == "" {
		return &FileConfig{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	return &cfg, nil
}

// Load resolves the full configuration by merging the config file with
// environment variables. Env vars always take precedence over file values.
//
// configPath is the path to the YAML config file. If empty, the
// TALOSCTL_OIDC_CONFIG env var is checked as a fallback.
func Load(configPath string) (*ResolvedConfig, error) {
	// Resolve config file path: flag > env var.
	if configPath == "" {
		configPath = os.Getenv("TALOSCTL_OIDC_CONFIG")
	}

	fileCfg, err := LoadFile(configPath)
	if err != nil {
		return nil, err
	}

	rc := &ResolvedConfig{}

	// Start with file values, then override with env vars.
	rc.CACert = envOrDefault("TALOSCTL_OIDC_CA_CERT", fileCfg.CACert)
	rc.CAKey = envOrDefault("TALOSCTL_OIDC_CA_KEY", fileCfg.CAKey)
	rc.CACertData = envOrDefault("TALOSCTL_OIDC_CA_CERT_DATA", fileCfg.CACertData)
	rc.CAKeyData = envOrDefault("TALOSCTL_OIDC_CA_KEY_DATA", fileCfg.CAKeyData)
	rc.TalosConfig = envOrDefault("TALOSCTL_OIDC_TALOS_CONFIG", fileCfg.TalosConfig)
	rc.IssuerURL = envOrDefault("TALOSCTL_OIDC_ISSUER_URL", fileCfg.IssuerURL)
	rc.ClientID = envOrDefault("TALOSCTL_OIDC_CLIENT_ID", fileCfg.ClientID)
	rc.ClientSecret = envOrDefault("TALOSCTL_OIDC_CLIENT_SECRET", fileCfg.ClientSecret)
	rc.Listen = envOrDefault("TALOSCTL_OIDC_LISTEN", fileCfg.Listen)
	rc.CertTTL = envOrDefault("TALOSCTL_OIDC_CERT_TTL", fileCfg.CertTTL)
	rc.TLSCert = envOrDefault("TALOSCTL_OIDC_TLS_CERT", fileCfg.TLSCert)
	rc.TLSKey = envOrDefault("TALOSCTL_OIDC_TLS_KEY", fileCfg.TLSKey)
	rc.DataDir = envOrDefault("TALOSCTL_OIDC_DATA_DIR", fileCfg.DataDir)
	rc.AuditLog = envOrDefault("TALOSCTL_OIDC_AUDIT_LOG", fileCfg.AuditLog)
	rc.AdminToken = envOrDefault("TALOSCTL_OIDC_ADMIN_TOKEN", fileCfg.AdminToken)

	// Endpoints: env var (comma-separated) > file (list).
	if envEndpoints := os.Getenv("TALOSCTL_OIDC_ENDPOINTS"); envEndpoints != "" {
		rc.Endpoints = strings.Split(envEndpoints, ",")
	} else if len(fileCfg.Endpoints) > 0 {
		rc.Endpoints = fileCfg.Endpoints
	}

	// Roles: env var (comma-separated) > file (list).
	if envRoles := os.Getenv("TALOSCTL_OIDC_ROLES"); envRoles != "" {
		rc.Roles = strings.Split(envRoles, ",")
	} else if len(fileCfg.Roles) > 0 {
		rc.Roles = fileCfg.Roles
	}

	// Insecure: env var > file.
	if envInsecure := os.Getenv("TALOSCTL_OIDC_INSECURE"); envInsecure != "" {
		rc.Insecure = strings.EqualFold(envInsecure, "true") || envInsecure == "1"
	} else {
		rc.Insecure = fileCfg.Insecure
	}

	return rc, nil
}

// Validate checks that all required fields are present and returns a
// descriptive error listing any missing configuration.
func (rc *ResolvedConfig) Validate() error {
	var missing []string
	if rc.TalosConfig == "" && rc.CACert == "" && rc.CACertData == "" {
		missing = append(missing, "ca_cert / TALOSCTL_OIDC_CA_CERT (or ca_cert_data / talos_config)")
	}
	if rc.TalosConfig == "" && rc.CAKey == "" && rc.CAKeyData == "" {
		missing = append(missing, "ca_key / TALOSCTL_OIDC_CA_KEY (or ca_key_data / talos_config)")
	}
	if rc.IssuerURL == "" {
		missing = append(missing, "issuer_url / TALOSCTL_OIDC_ISSUER_URL")
	}
	if rc.ClientID == "" {
		missing = append(missing, "client_id / TALOSCTL_OIDC_CLIENT_ID")
	}
	if len(rc.Endpoints) == 0 {
		missing = append(missing, "endpoints / TALOSCTL_OIDC_ENDPOINTS")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required configuration not set: %s", strings.Join(missing, ", "))
	}

	// Validate TLS configuration.
	if (rc.TLSCert != "") != (rc.TLSKey != "") {
		return fmt.Errorf("tls_cert and tls_key must both be set (or both unset)")
	}
	if rc.TLSCert != "" && rc.Insecure {
		return fmt.Errorf("cannot set both tls_cert and insecure=true")
	}

	return nil
}

// ApplyDefaults fills in default values for optional fields that are empty.
func (rc *ResolvedConfig) ApplyDefaults() {
	if rc.Listen == "" {
		rc.Listen = ":8443"
	}
	if len(rc.Roles) == 0 {
		rc.Roles = []string{"os:admin"}
	}
}

// ParseCertTTL parses the CertTTL string into a time.Duration.
// Returns 1h if empty.
func (rc *ResolvedConfig) ParseCertTTL() (time.Duration, error) {
	if rc.CertTTL == "" {
		return 1 * time.Hour, nil
	}
	d, err := time.ParseDuration(rc.CertTTL)
	if err != nil {
		return 0, fmt.Errorf("invalid cert_ttl %q: %w", rc.CertTTL, err)
	}
	return d, nil
}

// envOrDefault returns the environment variable value if set, otherwise the
// provided fallback.
func envOrDefault(envKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}
