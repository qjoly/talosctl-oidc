package oidc

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// normalizeIssuer trims trailing slashes from an issuer URL for comparison.
// Some providers (e.g. Authentik) include a trailing slash in the token's iss
// claim even when the configured issuer URL does not, or vice-versa. The OIDC
// spec treats these as equivalent.
func normalizeIssuer(iss string) string {
	return strings.TrimSuffix(iss, "/")
}

// ValidateHMACToken validates an HMAC-signed JWT using the golang-jwt/jwt library.
// This replaces the custom HMAC verification with a well-audited implementation.
func ValidateHMACToken(rawToken, clientSecret, expectedIssuer, expectedAudience string) (map[string]interface{}, error) {
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(60*time.Second),
	)

	token, err := parser.Parse(rawToken, func(t *jwt.Token) (interface{}, error) {
		// Validate algorithm is HMAC.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(clientSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	// Validate issuer with constant-time comparison.
	iss, _ := claims["iss"].(string)
	if subtle.ConstantTimeCompare([]byte(normalizeIssuer(iss)), []byte(normalizeIssuer(expectedIssuer))) != 1 {
		return nil, fmt.Errorf("issuer mismatch: got %q, expected %q", iss, expectedIssuer)
	}

	// Validate audience.
	if err := validateAudience(map[string]interface{}(claims), expectedAudience); err != nil {
		return nil, err
	}

	return map[string]interface{}(claims), nil
}
