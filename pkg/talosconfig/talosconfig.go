package talosconfig

import (
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
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA certificate: %w", err)
	}

	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("reading client certificate: %w", err)
	}

	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("reading client key: %w", err)
	}

	// Encode to base64 (talosconfig stores certs as base64).
	ctx := &Context{
		Endpoints: endpoints,
		CA:        base64.StdEncoding.EncodeToString(caCert),
		Crt:       base64.StdEncoding.EncodeToString(clientCert),
		Key:       base64.StdEncoding.EncodeToString(clientKey),
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
