package talosconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents a talosconfig file structure.
type Config struct {
	Context  string              `yaml:"context"`
	Contexts map[string]*Context `yaml:"contexts"`
}

// Context represents a single talosconfig context.
type Context struct {
	Endpoints []string `yaml:"endpoints"`
	Nodes     []string `yaml:"nodes,omitempty"`
	CA        string   `yaml:"ca"`
	Crt       string   `yaml:"crt"`
	Key       string   `yaml:"key"`
}

// DefaultPath returns the default talosconfig path.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".talos", "config"), nil
}

// Load reads and parses a talosconfig file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{
				Contexts: make(map[string]*Context),
			}, nil
		}
		return nil, fmt.Errorf("reading talosconfig: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing talosconfig: %w", err)
	}

	if config.Contexts == nil {
		config.Contexts = make(map[string]*Context)
	}

	return &config, nil
}

// Save writes the talosconfig to disk.
func Save(path string, config *Config) error {
	// Ensure the directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling talosconfig: %w", err)
	}

	// Write to a temporary file first for atomic replacement.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("writing temporary talosconfig: %w", err)
	}

	// Rename the temporary file to the final path.
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath) // clean up on failure
		return fmt.Errorf("replacing talosconfig: %w", err)
	}

	return nil
}

// GetCertificateExpiry parses the client certificate in the context and returns its expiry time.
func (c *Context) GetCertificateExpiry() (time.Time, error) {
	if c.Crt == "" {
		return time.Time{}, fmt.Errorf("no certificate in context")
	}

	decoded, err := base64.StdEncoding.DecodeString(c.Crt)
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding certificate: %w", err)
	}

	var block *pem.Block
	rest := decoded
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			break
		}
	}

	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// IsCertificateExpired reports whether the certificate in the context has expired
// or will expire within the given threshold.
func (c *Context) IsCertificateExpired(threshold time.Duration) bool {
	expiry, err := c.GetCertificateExpiry()
	if err != nil {
		return true // treat as expired if we can't parse it
	}
	return time.Now().Add(threshold).After(expiry)
}

// SetContextFromPEM adds or updates a context using raw PEM bytes (not file paths).
// This is used when receiving certificates from the cert exchange server.
func SetContextFromPEM(config *Config, name string, endpoints []string, caPEM, certPEM, keyPEM []byte) error {
	if len(caPEM) == 0 {
		return fmt.Errorf("CA certificate PEM is empty")
	}
	if len(certPEM) == 0 {
		return fmt.Errorf("client certificate PEM is empty")
	}
	if len(keyPEM) == 0 {
		return fmt.Errorf("client key PEM is empty")
	}

	ctx := &Context{
		Endpoints: endpoints,
		CA:        base64.StdEncoding.EncodeToString(bytes.TrimSpace(caPEM)),
		Crt:       base64.StdEncoding.EncodeToString(bytes.TrimSpace(certPEM)),
		Key:       base64.StdEncoding.EncodeToString(bytes.TrimSpace(keyPEM)),
	}

	config.Contexts[name] = ctx
	config.Context = name

	return nil
}

// RemoveContext removes a context from the talosconfig.
// If the removed context was the current one, the current context is cleared.
func RemoveContext(config *Config, name string) {
	delete(config.Contexts, name)
	if config.Context == name {
		config.Context = ""
	}
}

// HasContext reports whether a context with the given name exists.
func HasContext(config *Config, name string) bool {
	_, ok := config.Contexts[name]
	return ok
}
