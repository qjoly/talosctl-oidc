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

func debug(format string, v ...interface{}) {
	if os.Getenv("DEBUG") != "" {
		log.Printf("[DEBUG] "+format, v...)
	}
}

const (
	serviceName = "talosctl-oidc"
)

// Store saves the OIDC token to the system keychain, falling back to a file
// if the keychain is unavailable or the data is too large.
func Store(contextName string, token *oidc.StoredToken) error {
	debug("Storing token for context: %s", contextName)
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	debug("Attempting to store in keychain (size: %d bytes)", len(data))
	if err := keyring.Set(serviceName, contextName, string(data)); err != nil {
		log.Printf("Keychain unavailable (%v), using file-based token cache", err)
		return fileStore(contextName, token)
	}
	debug("Successfully stored in keychain")

	return nil
}

// Retrieve loads the OIDC token from the system keychain and the file cache,
// always checking both sources and returning the best token: one with a
// refresh token is preferred; if both (or neither) have a refresh token, the
// one that expires later wins.
func Retrieve(contextName string) (*oidc.StoredToken, error) {
	debug("Retrieving token for context: %s", contextName)

	var keychainToken *oidc.StoredToken
	data, err := keyring.Get(serviceName, contextName)
	if err == nil {
		var t oidc.StoredToken
		if jsonErr := json.Unmarshal([]byte(data), &t); jsonErr != nil {
			debug("Keychain token unmarshal failed: %v", jsonErr)
		} else {
			keychainToken = &t
			debug("Retrieved token from keychain (refresh_token present: %v, expires: %v)",
				keychainToken.RefreshToken != "", keychainToken.ExpiresAt)
		}
	} else {
		debug("Keychain retrieval failed: %v", err)
	}

	fileToken, fileErr := fileRetrieve(contextName)
	if fileErr != nil {
		debug("File cache retrieval failed: %v", fileErr)
	} else if fileToken != nil {
		debug("Retrieved token from file cache (refresh_token present: %v, expires: %v)",
			fileToken.RefreshToken != "", fileToken.ExpiresAt)
	}

	best := bestToken(keychainToken, fileToken)
	switch {
	case best == nil:
		debug("No token found in either keychain or file cache")
	case best == keychainToken && fileToken == nil:
		debug("Using keychain token (no file token)")
	case best == fileToken && keychainToken == nil:
		debug("Using file token (no keychain token)")
	case best == fileToken:
		debug("Preferring file token over keychain token (has refresh token or expires later)")
	default:
		debug("Preferring keychain token over file token (has refresh token or expires later)")
	}

	return best, nil
}

// bestToken returns the better of two tokens: the one with a refresh token is
// preferred; if both (or neither) have one, the one that expires later wins.
// A nil token is always worse than a non-nil one.
func bestToken(a, b *oidc.StoredToken) *oidc.StoredToken {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	// Prefer the one with a refresh token.
	aHas := a.RefreshToken != ""
	bHas := b.RefreshToken != ""
	if aHas && !bHas {
		return a
	}
	if bHas && !aHas {
		return b
	}
	// Both or neither have a refresh token — prefer the one expiring later.
	if b.ExpiresAt.After(a.ExpiresAt) {
		return b
	}
	return a
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
