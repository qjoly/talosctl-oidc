package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProviderConfig holds the OIDC provider discovery information.
type ProviderConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Discover fetches OIDC provider metadata from the well-known endpoint.
func Discover(ctx context.Context, issuerURL string) (*ProviderConfig, error) {
	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	debug("Fetching OIDC discovery from %s", wellKnown)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var config ProviderConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery document: %w", err)
	}
	debug("Discovery successful: issuer=%s, token_endpoint=%s", config.Issuer, config.TokenEndpoint)

	if config.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery: authorization_endpoint is empty")
	}
	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery: token_endpoint is empty")
	}

	return &config, nil
}

// TokenResponse represents the OIDC token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// StoredToken is what we persist in the keychain.
type StoredToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
}

// IsExpired reports whether the stored token has expired.
func (t *StoredToken) IsExpired() bool {
	// Consider expired 30 seconds before actual expiry to avoid edge cases.
	return time.Now().After(t.ExpiresAt.Add(-30 * time.Second))
}

// HasRefreshToken reports whether a refresh token is available.
func (t *StoredToken) HasRefreshToken() bool {
	return t.RefreshToken != ""
}

// PKCEChallenge holds the PKCE verifier and challenge for the auth flow.
type PKCEChallenge struct {
	Verifier  string
	Challenge string
	Method    string
}

// GeneratePKCE creates a new PKCE code verifier and challenge.
func GeneratePKCE() (*PKCEChallenge, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("generating PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

// BuildAuthorizationURL constructs the OIDC authorization URL.
func BuildAuthorizationURL(provider *ProviderConfig, clientID string, redirectURI string, scopes []string, state string, pkce *PKCEChallenge) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
		"access_type":           {"offline"}, // Required by some providers (like Google) for refresh tokens
		"prompt":                {"consent"}, // Often required to ensure offline_access is granted
	}

	return provider.AuthorizationEndpoint + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens.
func ExchangeCode(ctx context.Context, provider *ProviderConfig, clientID, clientSecret, code, redirectURI string, pkce *PKCEChallenge) (*TokenResponse, error) {
	debug("Exchanging code at %s for client_id=%s", provider.TokenEndpoint, clientID)
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {pkce.Verifier},
	}

	if clientSecret != "" {
		debug("Using client_secret for exchange")
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debug("Token exchange failed: status=%d, body=%s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	debug("Raw token response: %s", string(body))

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	debug("Token response: access_token=%v, refresh_token=%v, id_token=%v, expires_in=%d, scope=%q",
		tokenResp.AccessToken != "", tokenResp.RefreshToken != "", tokenResp.IDToken != "", tokenResp.ExpiresIn, tokenResp.Scope)

	return &tokenResp, nil
}

// RefreshAccessToken uses a refresh token to obtain new tokens.
func RefreshAccessToken(ctx context.Context, provider *ProviderConfig, clientID, clientSecret, refreshToken string, scopes []string) (*TokenResponse, error) {
	debug("Refreshing token at %s for client_id=%s, scopes=%v", provider.TokenEndpoint, clientID, scopes)
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	if len(scopes) > 0 {
		debug("Setting requested scopes for refresh: %v", scopes)
		data.Set("scope", strings.Join(scopes, " "))
	}

	if clientSecret != "" {
		debug("Using client_secret for refresh")
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		debug("Token refresh failed: status=%d, body=%s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("token refresh returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}
	debug("Raw refresh response: %s", string(body))

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding refresh response: %w", err)
	}
	debug("Refresh response: access_token=%v, refresh_token=%v, id_token=%v, expires_in=%d, scope=%q",
		tokenResp.AccessToken != "", tokenResp.RefreshToken != "", tokenResp.IDToken != "", tokenResp.ExpiresIn, tokenResp.Scope)

	return &tokenResp, nil
}
