package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"` // Key type: RSA, EC, OKP
	Use string `json:"use"` // Key use: sig, enc
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm: RS256, ES256, EdDSA, etc.

	// RSA fields
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC fields
	Crv string `json:"crv,omitempty"` // Curve: P-256, P-384, P-521
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate

	// OKP fields (Ed25519)
	// X is reused, Crv is "Ed25519"
}

// FetchJWKS fetches the JWKS from the given URI.
func FetchJWKS(ctx context.Context, jwksURI string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	resp.Body = http.MaxBytesReader(nil, resp.Body, 1<<20) // 1 MB limit

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	return &jwks, nil
}

// ValidateIDToken validates a JWT ID token against the given JWKS, issuer, and audience.
// For HS256/HS384/HS512 tokens, the clientSecret is used as the HMAC key.
// For asymmetric algorithms (RS256, ES256, EdDSA, etc.), the JWKS is used.
// It verifies:
//   - The token signature
//   - The issuer (iss) matches the expected issuer
//   - The audience (aud) contains the expected client ID
//   - The token is not expired (exp)
//   - The token is not used before its "not before" time (nbf), if present
//
// Returns the token claims on success.
func ValidateIDToken(rawToken string, jwks *JWKS, expectedIssuer, expectedAudience, clientSecret string) (map[string]interface{}, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT signature: %w", err)
	}

	switch header.Alg {
	case "HS256", "HS384", "HS512":
		// HMAC-based: use client secret as the key.
		if clientSecret == "" {
			return nil, fmt.Errorf("token uses %s but no client secret configured on the server", header.Alg)
		}
		if err := verifyHMAC(header.Alg, clientSecret, []byte(signingInput), signature); err != nil {
			return nil, fmt.Errorf("JWT signature verification failed: %w", err)
		}
	default:
		// Asymmetric: find key in JWKS.
		key, err := findKey(jwks, header.Kid, header.Alg)
		if err != nil {
			return nil, err
		}
		if err := verifySignature(header.Alg, key, []byte(signingInput), signature); err != nil {
			return nil, fmt.Errorf("JWT signature verification failed: %w", err)
		}
	}

	// Decode and validate claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT claims: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Validate issuer.
	// Normalize both sides by trimming trailing slashes: some providers (e.g. Authentik)
	// include a trailing slash in the token's iss claim even when the configured issuer URL
	// does not have one (or vice-versa). The OIDC spec treats these as equivalent.
	iss, _ := claims["iss"].(string)
	if strings.TrimSuffix(iss, "/") != strings.TrimSuffix(expectedIssuer, "/") {
		return nil, fmt.Errorf("issuer mismatch: got %q, expected %q", iss, expectedIssuer)
	}

	// Validate audience.
	if err := validateAudience(claims, expectedAudience); err != nil {
		return nil, err
	}

	// Validate expiry.
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < now {
			return nil, fmt.Errorf("token expired at %s", time.Unix(int64(exp), 0).Format(time.RFC3339))
		}
	} else {
		return nil, fmt.Errorf("token missing exp claim")
	}

	// Validate nbf (not before), if present.
	if nbf, ok := claims["nbf"].(float64); ok {
		if int64(nbf) > now+60 { // Allow 60 seconds of clock skew.
			return nil, fmt.Errorf("token not valid before %s", time.Unix(int64(nbf), 0).Format(time.RFC3339))
		}
	}

	return claims, nil
}

// findKey finds the matching JWK for the given kid and algorithm.
func findKey(jwks *JWKS, kid, alg string) (*JWK, error) {
	for i := range jwks.Keys {
		k := &jwks.Keys[i]
		// If kid is specified, match on it.
		if kid != "" && k.Kid == kid {
			return k, nil
		}
		// If no kid in header, match by algorithm compatibility.
		if kid == "" {
			if isAlgCompatible(k, alg) {
				return k, nil
			}
		}
	}

	if kid != "" {
		return nil, fmt.Errorf("no matching key found in JWKS for kid=%q", kid)
	}
	return nil, fmt.Errorf("no matching key found in JWKS for alg=%q", alg)
}

// isAlgCompatible checks if a JWK is compatible with the given algorithm.
func isAlgCompatible(key *JWK, alg string) bool {
	if key.Alg != "" {
		return key.Alg == alg
	}
	switch alg {
	case "RS256", "RS384", "RS512":
		return key.Kty == "RSA"
	case "ES256", "ES384", "ES512":
		return key.Kty == "EC"
	case "EdDSA":
		return key.Kty == "OKP"
	}
	return false
}

// verifySignature verifies a JWT signature using the appropriate algorithm.
func verifySignature(alg string, key *JWK, signingInput, signature []byte) error {
	switch alg {
	case "RS256":
		return verifyRSA(key, crypto.SHA256, signingInput, signature)
	case "RS384":
		return verifyRSA(key, crypto.SHA384, signingInput, signature)
	case "RS512":
		return verifyRSA(key, crypto.SHA512, signingInput, signature)
	case "ES256":
		return verifyECDSA(key, crypto.SHA256, elliptic.P256(), signingInput, signature)
	case "ES384":
		return verifyECDSA(key, crypto.SHA384, elliptic.P384(), signingInput, signature)
	case "ES512":
		return verifyECDSA(key, crypto.SHA512, elliptic.P521(), signingInput, signature)
	case "EdDSA":
		return verifyEdDSA(key, signingInput, signature)
	default:
		return fmt.Errorf("unsupported JWT algorithm: %s", alg)
	}
}

// verifyRSA verifies an RSA signature.
func verifyRSA(key *JWK, hashAlg crypto.Hash, signingInput, signature []byte) error {
	if key.Kty != "RSA" {
		return fmt.Errorf("expected RSA key, got %s", key.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("decoding RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("decoding RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(signingInput)
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, hashAlg, digest, signature)
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(key *JWK, hashAlg crypto.Hash, curve elliptic.Curve, signingInput, signature []byte) error {
	if key.Kty != "EC" {
		return fmt.Errorf("expected EC key, got %s", key.Kty)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return fmt.Errorf("decoding EC X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return fmt.Errorf("decoding EC Y coordinate: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm")
	}

	h.Write(signingInput)
	digest := h.Sum(nil)

	// ECDSA JWT signatures are r||s concatenated (not ASN.1 DER).
	keySize := (curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length: expected %d, got %d", 2*keySize, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyEdDSA verifies an EdDSA (Ed25519) signature.
func verifyEdDSA(key *JWK, signingInput, signature []byte) error {
	if key.Kty != "OKP" {
		return fmt.Errorf("expected OKP key, got %s", key.Kty)
	}
	if key.Crv != "Ed25519" {
		return fmt.Errorf("unsupported OKP curve: %s", key.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return fmt.Errorf("decoding Ed25519 public key: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	pubKey := ed25519.PublicKey(xBytes)

	if !ed25519.Verify(pubKey, signingInput, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// verifyHMAC verifies an HMAC-SHA signature (HS256, HS384, HS512).
func verifyHMAC(alg, secret string, signingInput, signature []byte) error {
	var h func() hash.Hash
	switch alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	default:
		return fmt.Errorf("unsupported HMAC algorithm: %s", alg)
	}

	mac := hmac.New(h, []byte(secret))
	mac.Write(signingInput)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signature, expectedMAC) {
		return fmt.Errorf("HMAC signature mismatch")
	}

	return nil
}

// validateAudience checks that the expected audience is present in the token claims.
func validateAudience(claims map[string]interface{}, expectedAudience string) error {
	aud, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("token missing aud claim")
	}

	switch v := aud.(type) {
	case string:
		if v != expectedAudience {
			return fmt.Errorf("audience mismatch: got %q, expected %q", v, expectedAudience)
		}
	case []interface{}:
		found := false
		for _, a := range v {
			if s, ok := a.(string); ok && s == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience %q not found in token audiences", expectedAudience)
		}
	default:
		return fmt.Errorf("unexpected aud claim type: %T", aud)
	}

	return nil
}
