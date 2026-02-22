package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile_Empty(t *testing.T) {
	cfg, err := LoadFile("")
	if err != nil {
		t.Fatalf("LoadFile('') returned error: %v", err)
	}
	if cfg.IssuerURL != "" {
		t.Errorf("expected empty IssuerURL, got %q", cfg.IssuerURL)
	}
}

func TestLoadFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
issuer_url: https://example.com
client_id: my-client
endpoints:
  - 10.0.0.1
  - 10.0.0.2
listen: ":9090"
cert_ttl: "2h"
roles:
  - os:reader
  - os:admin
insecure: true
ca_cert: /tmp/ca.crt
ca_key: /tmp/ca.key
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}

	if cfg.IssuerURL != "https://example.com" {
		t.Errorf("IssuerURL = %q, want %q", cfg.IssuerURL, "https://example.com")
	}
	if cfg.ClientID != "my-client" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "my-client")
	}
	if len(cfg.Endpoints) != 2 || cfg.Endpoints[0] != "10.0.0.1" {
		t.Errorf("Endpoints = %v, want [10.0.0.1 10.0.0.2]", cfg.Endpoints)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9090")
	}
	if cfg.CertTTL != "2h" {
		t.Errorf("CertTTL = %q, want %q", cfg.CertTTL, "2h")
	}
	if len(cfg.Roles) != 2 || cfg.Roles[0] != "os:reader" {
		t.Errorf("Roles = %v, want [os:reader os:admin]", cfg.Roles)
	}
	if !cfg.Insecure {
		t.Error("Insecure = false, want true")
	}
}

func TestLoadFile_NotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
issuer_url: https://from-file.example.com
client_id: file-client
endpoints:
  - 10.0.0.1
ca_cert: /file/ca.crt
ca_key: /file/ca.key
listen: ":9090"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	// Set env vars that should override file values.
	t.Setenv("TALOSCTL_OIDC_ISSUER_URL", "https://from-env.example.com")
	t.Setenv("TALOSCTL_OIDC_ENDPOINTS", "192.168.1.1,192.168.1.2")

	// Clear env vars that should NOT be set (so file value comes through).
	t.Setenv("TALOSCTL_OIDC_CLIENT_ID", "")
	t.Setenv("TALOSCTL_OIDC_LISTEN", "")
	t.Setenv("TALOSCTL_OIDC_CA_CERT", "")
	t.Setenv("TALOSCTL_OIDC_CA_KEY", "")

	rc, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Env var should win.
	if rc.IssuerURL != "https://from-env.example.com" {
		t.Errorf("IssuerURL = %q, want env value %q", rc.IssuerURL, "https://from-env.example.com")
	}

	// Env var endpoints should win.
	if len(rc.Endpoints) != 2 || rc.Endpoints[0] != "192.168.1.1" {
		t.Errorf("Endpoints = %v, want [192.168.1.1 192.168.1.2]", rc.Endpoints)
	}

	// File values should come through when env is empty.
	if rc.ClientID != "file-client" {
		t.Errorf("ClientID = %q, want file value %q", rc.ClientID, "file-client")
	}
	if rc.Listen != ":9090" {
		t.Errorf("Listen = %q, want file value %q", rc.Listen, ":9090")
	}
	if rc.CACert != "/file/ca.crt" {
		t.Errorf("CACert = %q, want file value %q", rc.CACert, "/file/ca.crt")
	}
}

func TestLoad_ConfigEnvVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
issuer_url: https://via-env-config.example.com
client_id: env-config-client
endpoints:
  - 10.0.0.1
ca_cert: /tmp/ca.crt
ca_key: /tmp/ca.key
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	// Set the config file via env var (no flag).
	t.Setenv("TALOSCTL_OIDC_CONFIG", path)

	// Clear env vars to let file values through.
	t.Setenv("TALOSCTL_OIDC_ISSUER_URL", "")
	t.Setenv("TALOSCTL_OIDC_CLIENT_ID", "")
	t.Setenv("TALOSCTL_OIDC_ENDPOINTS", "")
	t.Setenv("TALOSCTL_OIDC_CA_CERT", "")
	t.Setenv("TALOSCTL_OIDC_CA_KEY", "")

	rc, err := Load("") // empty string = check TALOSCTL_OIDC_CONFIG env
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if rc.IssuerURL != "https://via-env-config.example.com" {
		t.Errorf("IssuerURL = %q, want %q", rc.IssuerURL, "https://via-env-config.example.com")
	}
	if rc.ClientID != "env-config-client" {
		t.Errorf("ClientID = %q, want %q", rc.ClientID, "env-config-client")
	}
}

func TestLoad_EnvOnlyNoFile(t *testing.T) {
	// Clear any config file env.
	t.Setenv("TALOSCTL_OIDC_CONFIG", "")

	t.Setenv("TALOSCTL_OIDC_ISSUER_URL", "https://env-only.example.com")
	t.Setenv("TALOSCTL_OIDC_CLIENT_ID", "env-only-client")
	t.Setenv("TALOSCTL_OIDC_ENDPOINTS", "1.2.3.4")
	t.Setenv("TALOSCTL_OIDC_CA_CERT", "/env/ca.crt")
	t.Setenv("TALOSCTL_OIDC_CA_KEY", "/env/ca.key")
	t.Setenv("TALOSCTL_OIDC_LISTEN", ":7070")
	t.Setenv("TALOSCTL_OIDC_ROLES", "os:reader")

	rc, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if rc.IssuerURL != "https://env-only.example.com" {
		t.Errorf("IssuerURL = %q", rc.IssuerURL)
	}
	if rc.Listen != ":7070" {
		t.Errorf("Listen = %q, want :7070", rc.Listen)
	}
	if len(rc.Roles) != 1 || rc.Roles[0] != "os:reader" {
		t.Errorf("Roles = %v, want [os:reader]", rc.Roles)
	}
}

func TestResolvedConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rc      ResolvedConfig
		wantErr bool
	}{
		{
			name: "valid with ca files",
			rc: ResolvedConfig{
				CACert:    "/ca.crt",
				CAKey:     "/ca.key",
				IssuerURL: "https://example.com",
				ClientID:  "client",
				Endpoints: []string{"10.0.0.1"},
			},
		},
		{
			name: "valid with inline data",
			rc: ResolvedConfig{
				CACertData: "---BEGIN CERT---",
				CAKeyData:  "---BEGIN KEY---",
				IssuerURL:  "https://example.com",
				ClientID:   "client",
				Endpoints:  []string{"10.0.0.1"},
			},
		},
		{
			name: "valid with talos config",
			rc: ResolvedConfig{
				TalosConfig: "/talosconfig",
				IssuerURL:   "https://example.com",
				ClientID:    "client",
				Endpoints:   []string{"10.0.0.1"},
			},
		},
		{
			name: "missing CA",
			rc: ResolvedConfig{
				IssuerURL: "https://example.com",
				ClientID:  "client",
				Endpoints: []string{"10.0.0.1"},
			},
			wantErr: true,
		},
		{
			name: "missing issuer",
			rc: ResolvedConfig{
				CACert:    "/ca.crt",
				CAKey:     "/ca.key",
				ClientID:  "client",
				Endpoints: []string{"10.0.0.1"},
			},
			wantErr: true,
		},
		{
			name: "missing endpoints",
			rc: ResolvedConfig{
				CACert:    "/ca.crt",
				CAKey:     "/ca.key",
				IssuerURL: "https://example.com",
				ClientID:  "client",
			},
			wantErr: true,
		},
		{
			name: "tls_cert without tls_key",
			rc: ResolvedConfig{
				CACert:    "/ca.crt",
				CAKey:     "/ca.key",
				IssuerURL: "https://example.com",
				ClientID:  "client",
				Endpoints: []string{"10.0.0.1"},
				TLSCert:   "/tls.crt",
			},
			wantErr: true,
		},
		{
			name: "tls_cert with insecure",
			rc: ResolvedConfig{
				CACert:    "/ca.crt",
				CAKey:     "/ca.key",
				IssuerURL: "https://example.com",
				ClientID:  "client",
				Endpoints: []string{"10.0.0.1"},
				TLSCert:   "/tls.crt",
				TLSKey:    "/tls.key",
				Insecure:  true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rc.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolvedConfig_ApplyDefaults(t *testing.T) {
	rc := &ResolvedConfig{}
	rc.ApplyDefaults()

	if rc.Listen != ":8443" {
		t.Errorf("Listen = %q, want :8443", rc.Listen)
	}
	if len(rc.Roles) != 1 || rc.Roles[0] != "os:admin" {
		t.Errorf("Roles = %v, want [os:admin]", rc.Roles)
	}
}

func TestResolvedConfig_ApplyDefaults_NoOverride(t *testing.T) {
	rc := &ResolvedConfig{
		Listen: ":9090",
		Roles:  []string{"os:reader"},
	}
	rc.ApplyDefaults()

	if rc.Listen != ":9090" {
		t.Errorf("Listen = %q, want :9090 (should not override)", rc.Listen)
	}
	if len(rc.Roles) != 1 || rc.Roles[0] != "os:reader" {
		t.Errorf("Roles = %v, want [os:reader] (should not override)", rc.Roles)
	}
}

func TestResolvedConfig_ParseCertTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     string
		want    string
		wantErr bool
	}{
		{"empty defaults to 1h", "", "1h0m0s", false},
		{"valid 2h", "2h", "2h0m0s", false},
		{"valid 30m", "30m", "30m0s", false},
		{"invalid", "xyz", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &ResolvedConfig{CertTTL: tt.ttl}
			d, err := rc.ParseCertTTL()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertTTL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && d.String() != tt.want {
				t.Errorf("ParseCertTTL() = %s, want %s", d, tt.want)
			}
		})
	}
}

func TestLoad_InsecureEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
issuer_url: https://example.com
client_id: test
endpoints:
  - 10.0.0.1
ca_cert: /ca.crt
ca_key: /ca.key
insecure: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test config: %v", err)
	}

	// Clear other env vars.
	t.Setenv("TALOSCTL_OIDC_ISSUER_URL", "")
	t.Setenv("TALOSCTL_OIDC_CLIENT_ID", "")
	t.Setenv("TALOSCTL_OIDC_ENDPOINTS", "")
	t.Setenv("TALOSCTL_OIDC_CA_CERT", "")
	t.Setenv("TALOSCTL_OIDC_CA_KEY", "")

	// Env var sets insecure=true, overriding file's false.
	t.Setenv("TALOSCTL_OIDC_INSECURE", "true")

	rc, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if !rc.Insecure {
		t.Error("Insecure should be true (env override), got false")
	}
}
