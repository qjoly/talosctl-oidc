package talosconfig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

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
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".talos", "config")
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

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing talosconfig: %w", err)
	}

	return nil
}

// SetContext adds or updates a context in the talosconfig with the given certificates
// and sets it as the current context.
func SetContext(config *Config, name string, endpoints []string, caCertPath, clientCertPath, clientKeyPath string) error {
	// Read certificate files.
	caCert, err := readAndEncode(caCertPath, "CA certificate")
	if err != nil {
		return err
	}

	clientCert, err := readAndEncode(clientCertPath, "client certificate")
	if err != nil {
		return err
	}

	clientKey, err := readAndEncode(clientKeyPath, "client key")
	if err != nil {
		return err
	}

	ctx := &Context{
		Endpoints: endpoints,
		CA:        caCert,
		Crt:       clientCert,
		Key:       clientKey,
	}

	config.Contexts[name] = ctx
	config.Context = name

	return nil
}

// readAndEncode reads a file and returns its content as base64.
// It handles three formats:
//   - PEM (-----BEGIN ...) → base64-encode as-is
//   - Already base64-encoded PEM → use as-is (decoded content starts with -----BEGIN)
//   - Other → error
func readAndEncode(path string, label string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", label, err)
	}

	content := bytes.TrimSpace(data)
	if len(content) == 0 {
		return "", fmt.Errorf("%s file is empty: %s", label, path)
	}

	// Case 1: File contains PEM directly.
	if bytes.HasPrefix(content, []byte("-----BEGIN ")) {
		return base64.StdEncoding.EncodeToString(content), nil
	}

	// Case 2: File contains base64-encoded PEM (e.g. extracted from a talosconfig).
	decoded, err := base64.StdEncoding.DecodeString(string(content))
	if err == nil && bytes.HasPrefix(bytes.TrimSpace(decoded), []byte("-----BEGIN ")) {
		// Already valid base64-encoded PEM, use as-is.
		return string(content), nil
	}

	return "", fmt.Errorf("%s file is not a valid PEM or base64-encoded PEM: %s (file is %d bytes)", label, path, len(content))
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
