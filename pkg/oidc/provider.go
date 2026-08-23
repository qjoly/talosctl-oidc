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

// oidcHTTPClient is a shared HTTP client with timeouts for all OIDC outbound calls.
var oidcHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	},
}

// postForm sends a form-encoded POST to endpoint and returns the status and body.
func postForm(ctx context.Context, endpoint string, data url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("creating request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	resp.Body = http.MaxBytesReader(nil, resp.Body, 1<<20) // 1 MB limit

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response from %s: %w", endpoint, err)
	}

	return resp.StatusCode, body, nil
}

// ProviderConfig holds the OIDC provider discovery information.
type ProviderConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// Discover fetches OIDC provider metadata from the well-known endpoint.
func Discover(ctx context.Context, issuerURL string) (*ProviderConfig, error) {
	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	debug("Fetching OIDC discovery from %s", wellKnown)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()
	resp.Body = http.MaxBytesReader(nil, resp.Body, 1<<20) // 1 MB limit

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

	status, body, err := postForm(ctx, provider.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}

	if status != http.StatusOK {
		debug("Token exchange failed: status=%d, body=%s", status, string(body))
		return nil, fmt.Errorf("token endpoint returned status %d: %s", status, string(body))
	}

	var tokenResp TokenResponse
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

	status, body, err := postForm(ctx, provider.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("refreshing token: %w", err)
	}

	if status != http.StatusOK {
		debug("Token refresh failed: status=%d, body=%s", status, string(body))
		return nil, fmt.Errorf("token refresh returned status %d: %s", status, string(body))
	}

	var tokenResp TokenResponse
	debug("Raw refresh response: %s", string(body))

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding refresh response: %w", err)
	}
	debug("Refresh response: access_token=%v, refresh_token=%v, id_token=%v, expires_in=%d, scope=%q",
		tokenResp.AccessToken != "", tokenResp.RefreshToken != "", tokenResp.IDToken != "", tokenResp.ExpiresIn, tokenResp.Scope)

	return &tokenResp, nil
}

// deviceCodeGrantType is the grant_type of RFC 8628.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuth is the device authorization response (RFC 8628 section 3.2).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// RequestDeviceCode starts a device authorization grant.
func RequestDeviceCode(ctx context.Context, provider *ProviderConfig, clientID, clientSecret string, scopes []string) (*DeviceAuth, error) {
	if provider.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("the OIDC provider does not advertise a device_authorization_endpoint; enable the device flow for this client")
	}
	debug("Requesting device code at %s for client_id=%s", provider.DeviceAuthorizationEndpoint, clientID)

	data := url.Values{"client_id": {clientID}}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	status, body, err := postForm(ctx, provider.DeviceAuthorizationEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("device authorization endpoint returned status %d: %s", status, string(body))
	}

	var auth DeviceAuth
	if err := json.Unmarshal(body, &auth); err != nil {
		return nil, fmt.Errorf("decoding device authorization response: %w", err)
	}
	if auth.DeviceCode == "" || auth.UserCode == "" {
		return nil, fmt.Errorf("device authorization response is missing device_code or user_code")
	}

	// Defaults from RFC 8628 section 3.2 when the provider stays silent.
	if auth.Interval <= 0 {
		auth.Interval = 5
	}
	if auth.ExpiresIn <= 0 {
		auth.ExpiresIn = 600
	}
	debug("Device code obtained: user_code=%s, interval=%ds, expires_in=%ds", auth.UserCode, auth.Interval, auth.ExpiresIn)

	return &auth, nil
}

// PollDeviceToken polls the token endpoint until the user approves the request,
// the device code expires, or ctx is cancelled.
func PollDeviceToken(ctx context.Context, provider *ProviderConfig, clientID, clientSecret string, auth *DeviceAuth) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":  {deviceCodeGrantType},
		"device_code": {auth.DeviceCode},
		"client_id":   {clientID},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	interval := time.Duration(auth.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device code expired before the login was approved")
		}

		status, body, err := postForm(ctx, provider.TokenEndpoint, data)
		if err != nil {
			return nil, fmt.Errorf("polling for the device token: %w", err)
		}

		if status == http.StatusOK {
			var tokenResp TokenResponse
			if err := json.Unmarshal(body, &tokenResp); err != nil {
				return nil, fmt.Errorf("decoding device token response: %w", err)
			}
			debug("Device token response: access_token=%v, refresh_token=%v, id_token=%v",
				tokenResp.AccessToken != "", tokenResp.RefreshToken != "", tokenResp.IDToken != "")
			return &tokenResp, nil
		}

		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) != nil || errResp.Error == "" {
			return nil, fmt.Errorf("token endpoint returned status %d: %s", status, string(body))
		}

		switch errResp.Error {
		case "authorization_pending":
			debug("Device authorization still pending")
		case "slow_down":
			// RFC 8628 section 3.5: bump the interval by 5s and keep going.
			interval += 5 * time.Second
			debug("Provider asked to slow down, polling every %s", interval)
		default:
			return nil, fmt.Errorf("device authorization failed: %s: %s", errResp.Error, errResp.Description)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}
