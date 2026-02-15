package keychain

import (
	"encoding/json"
	"fmt"

	"github.com/zalando/go-keyring"

	"github.com/qjoly/talosctl-oidc/pkg/oidc"
)

const (
	serviceName = "talosctl-oidc"
)

// Store saves the OIDC token to the system keychain.
func Store(contextName string, token *oidc.StoredToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	if err := keyring.Set(serviceName, contextName, string(data)); err != nil {
		return fmt.Errorf("storing token in keychain: %w", err)
	}

	return nil
}

// Retrieve loads the OIDC token from the system keychain.
func Retrieve(contextName string) (*oidc.StoredToken, error) {
	data, err := keyring.Get(serviceName, contextName)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("retrieving token from keychain: %w", err)
	}

	var token oidc.StoredToken
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil, fmt.Errorf("unmarshaling token: %w", err)
	}

	return &token, nil
}

// Delete removes the OIDC token from the system keychain.
func Delete(contextName string) error {
	err := keyring.Delete(serviceName, contextName)
	if err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("deleting token from keychain: %w", err)
	}
	return nil
}
