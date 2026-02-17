package keychain

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"

	"github.com/qjoly/talosctl-oidc/pkg/oidc"
)

const (
	serviceName = "talosctl-oidc"
)

// Store saves the OIDC token to the system keychain, falling back to a file
// if the keychain is unavailable or the data is too large.
func Store(contextName string, token *oidc.StoredToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	if err := keyring.Set(serviceName, contextName, string(data)); err != nil {
		log.Printf("Keychain unavailable (%v), using file-based token cache", err)
		return fileStore(contextName, token)
	}

	return nil
}

// Retrieve loads the OIDC token from the system keychain, falling back to a
// file if the keychain is unavailable.
func Retrieve(contextName string) (*oidc.StoredToken, error) {
	data, err := keyring.Get(serviceName, contextName)
	if err == nil {
		var token oidc.StoredToken
		if err := json.Unmarshal([]byte(data), &token); err != nil {
			return nil, fmt.Errorf("unmarshaling token: %w", err)
		}
		return &token, nil
	}

	if err != keyring.ErrNotFound {
		// Keychain error (not just "key missing") — try file fallback.
		return fileRetrieve(contextName)
	}

	// Key not found in keychain — also check file fallback (may have been
	// stored there on a previous run where keychain was too small).
	return fileRetrieve(contextName)
}

// Delete removes the OIDC token from the system keychain and the file cache.
func Delete(contextName string) error {
	// Try both — ignore individual errors so we clean up everywhere.
	keyringErr := keyring.Delete(serviceName, contextName)
	if keyringErr != nil && keyringErr != keyring.ErrNotFound {
		log.Printf("Warning: could not delete from keychain: %v", keyringErr)
	}

	fileErr := fileDelete(contextName)
	if fileErr != nil && !os.IsNotExist(fileErr) {
		log.Printf("Warning: could not delete file cache: %v", fileErr)
	}

	return nil
}

// ---------------------------------------------------------------------------
// File-based fallback
// ---------------------------------------------------------------------------
//
// Tokens are stored as a JSON object keyed by context name in a single file:
//   ~/.config/talosctl-oidc/tokens.json  (mode 0600)

var fileMu sync.Mutex

// cacheDir returns the directory used for the file-based token cache.
func cacheDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		home, err2 := os.UserHomeDir()
		if err2 != nil {
			return "", fmt.Errorf("unable to determine config directory: %w (home: %v)", err, err2)
		}
		cfgDir = filepath.Join(home, ".config")
	}
	return filepath.Join(cfgDir, serviceName), nil
}

func cacheFilePath() (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tokens.json"), nil
}

// tokenMap is the on-disk format: context-name → StoredToken.
type tokenMap map[string]*oidc.StoredToken

func readTokenFile() (tokenMap, string, error) {
	path, err := cacheFilePath()
	if err != nil {
		return nil, "", err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(tokenMap), path, nil
		}
		return nil, path, fmt.Errorf("reading token cache %s: %w", path, err)
	}

	var m tokenMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, path, fmt.Errorf("parsing token cache %s: %w", path, err)
	}

	if m == nil {
		m = make(tokenMap)
	}

	return m, path, nil
}

func writeTokenFile(path string, m tokenMap) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating cache directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token cache: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing token cache %s: %w", path, err)
	}

	return nil
}

func fileStore(contextName string, token *oidc.StoredToken) error {
	fileMu.Lock()
	defer fileMu.Unlock()

	m, path, err := readTokenFile()
	if err != nil {
		return err
	}

	m[contextName] = token

	if err := writeTokenFile(path, m); err != nil {
		return err
	}

	log.Printf("Token cached in %s", path)
	return nil
}

func fileRetrieve(contextName string) (*oidc.StoredToken, error) {
	fileMu.Lock()
	defer fileMu.Unlock()

	m, _, err := readTokenFile()
	if err != nil {
		return nil, err
	}

	token, ok := m[contextName]
	if !ok {
		return nil, nil
	}

	return token, nil
}

func fileDelete(contextName string) error {
	fileMu.Lock()
	defer fileMu.Unlock()

	m, path, err := readTokenFile()
	if err != nil {
		return err
	}

	if _, ok := m[contextName]; !ok {
		return nil
	}

	delete(m, contextName)

	if len(m) == 0 {
		return os.Remove(path)
	}

	return writeTokenFile(path, m)
}
