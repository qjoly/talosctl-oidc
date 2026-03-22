package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func makeJWT(t *testing.T, header, claims map[string]interface{}, signFn func(input string) (string, error)) string {
	t.Helper()
	hJSON, _ := json.Marshal(header)
	cJSON, _ := json.Marshal(claims)
	hEnc := base64.RawURLEncoding.EncodeToString(hJSON)
	cEnc := base64.RawURLEncoding.EncodeToString(cJSON)
	input := hEnc + "." + cEnc
	sig, err := signFn(input)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return input + "." + sig
}

func TestValidateAudience_String(t *testing.T) {
	claims := map[string]interface{}{"aud": "my-client"}
	if err := validateAudience(claims, "my-client"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateAudience_StringMismatch(t *testing.T) {
	claims := map[string]interface{}{"aud": "wrong-client"}
	if err := validateAudience(claims, "my-client"); err == nil {
		t.Error("expected error for audience mismatch")
	}
}

func TestValidateAudience_Array(t *testing.T) {
	claims := map[string]interface{}{"aud": []interface{}{"other", "my-client"}}
	if err := validateAudience(claims, "my-client"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateAudience_ArrayNotFound(t *testing.T) {
	claims := map[string]interface{}{"aud": []interface{}{"other", "another"}}
	if err := validateAudience(claims, "my-client"); err == nil {
		t.Error("expected error when audience not in array")
	}
}

func TestValidateAudience_Missing(t *testing.T) {
	claims := map[string]interface{}{}
	if err := validateAudience(claims, "my-client"); err == nil {
		t.Error("expected error for missing aud claim")
	}
}

func TestValidateIDToken_Expired(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "client-id",
		"exp": float64(now - 3600), // expired 1 hour ago
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidateIDToken_ValidHS256(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "client-id",
		"exp": float64(now + 3600), // expires in 1 hour
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	result, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err != nil {
		t.Fatalf("expected no error for valid token, got %v", err)
	}
	if sub, _ := result["sub"].(string); sub != "user-123" {
		t.Errorf("expected sub %q, got %q", "user-123", sub)
	}
}

func TestValidateIDToken_IssuerTrailingSlash(t *testing.T) {
	now := time.Now().Unix()
	// Token has trailing slash in iss claim
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com/",
		"aud": "client-id",
		"exp": float64(now + 3600),
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	// Expected issuer without trailing slash — should still match
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err != nil {
		t.Errorf("expected issuer trailing slash to be normalized, got error: %v", err)
	}
}

func TestValidateIDToken_IssuerMismatch(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://other-issuer.example.com",
		"aud": "client-id",
		"exp": float64(now + 3600),
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestValidateIDToken_AudienceMismatch(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "wrong-client",
		"exp": float64(now + 3600),
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err == nil {
		t.Error("expected error for audience mismatch")
	}
}

func TestValidateIDToken_InvalidSignature(t *testing.T) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "client-id",
		"exp": float64(now + 3600),
		"sub": "user-123",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte("correct-secret"))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	// Validate with wrong secret
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", "wrong-secret")
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestValidateIDToken_MissingExpClaim(t *testing.T) {
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "client-id",
		"sub": "user-123",
		// no "exp"
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	secret := "test-secret"
	token := makeJWT(t, header, claims, func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	})
	_, err := ValidateIDToken(token, nil, "https://issuer.example.com", "client-id", secret)
	if err == nil {
		t.Error("expected error for token missing exp claim")
	}
}
