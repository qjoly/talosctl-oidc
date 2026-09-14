package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// The fuzz targets below guard the untrusted-input surface of the token path.
// Everything they parse comes straight off the wire — the ID token from the
// user's browser, the JWKS from the OIDC provider — so the contract is that no
// input, however malformed, may panic. A validation error is always an
// acceptable outcome; a crash is not.
//
// Run longer campaigns with:
//
//	go test ./pkg/oidc/ -run=Fuzz -fuzz=FuzzValidateIDToken -fuzztime=5m

// testJWKS returns a JWKS with one key per supported asymmetric family, so the
// fuzzer can reach the signature-verification code paths instead of bailing out
// early on "key not found".
func testJWKS() *JWKS {
	return &JWKS{
		Keys: []JWK{
			{Kty: "RSA", Kid: "rsa-1", Alg: "RS256", Use: "sig",
				N: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
					"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
					"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7" +
					"svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2" +
					"EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-V" +
					"TdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
				E: "AQAB"},
			{Kty: "EC", Kid: "ec-1", Alg: "ES256", Use: "sig", Crv: "P-256",
				X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				Y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
			{Kty: "OKP", Kid: "ed-1", Alg: "EdDSA", Use: "sig", Crv: "Ed25519",
				X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
		},
	}
}

// FuzzValidateIDToken drives the full token-validation pipeline: the dot split,
// the base64 decoding of each segment, the JSON decoding of the header and
// claims, the algorithm allowlist, key lookup and signature verification.
func FuzzValidateIDToken(f *testing.F) {
	jwks := testJWKS()

	// A well-formed HS256 token, so the corpus starts from something that gets
	// past the structural checks and reaches claim validation.
	hmacSign := func(input string) (string, error) {
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write([]byte(input))
		return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	}
	hJSON, _ := json.Marshal(map[string]interface{}{"alg": "HS256", "typ": "JWT"})
	cJSON, _ := json.Marshal(map[string]interface{}{
		"iss": "https://issuer.example.com",
		"aud": "my-client",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	input := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(cJSON)
	sig, _ := hmacSign(input)
	f.Add(input+"."+sig, "https://issuer.example.com", "my-client", "secret")

	// Structural edge cases: empty, wrong segment count, non-base64, the
	// "none" algorithm, and a header claiming a key that does not exist.
	f.Add("", "", "", "")
	f.Add("a.b", "iss", "aud", "")
	f.Add("a.b.c", "iss", "aud", "")
	f.Add("....", "iss", "aud", "")
	f.Add("!!!.???.***", "iss", "aud", "")
	f.Add("eyJhbGciOiJub25lIn0..", "iss", "aud", "")
	f.Add("eyJhbGciOiJSUzI1NiIsImtpZCI6Im5vcGUifQ.e30.AA", "iss", "aud", "")

	f.Fuzz(func(t *testing.T, rawToken, issuer, audience, secret string) {
		// Must not panic. Any error is fine; claims are only meaningful on success.
		claims, err := ValidateIDToken(rawToken, jwks, issuer, audience, secret, nil)
		if err == nil && claims == nil {
			t.Fatal("ValidateIDToken returned no error but nil claims")
		}
	})
}

// FuzzValidateIDTokenAllowedAlgs fuzzes the algorithm allowlist itself, which
// is operator-controlled but must never let "none" or an empty alg through.
func FuzzValidateIDTokenAllowedAlgs(f *testing.F) {
	jwks := testJWKS()

	f.Add("eyJhbGciOiJub25lIn0.e30.", "none")
	f.Add("eyJhbGciOiJub25lIn0.e30.", "")
	f.Add("eyJhbGciOiJIUzI1NiJ9.e30.AA", "HS256")
	f.Add("eyJhbGciOiJSUzI1NiJ9.e30.AA", "RS256,ES256")

	f.Fuzz(func(t *testing.T, rawToken, allowedAlgsCSV string) {
		allowedAlgs := splitCSV(allowedAlgsCSV)

		claims, err := ValidateIDToken(rawToken, jwks, "iss", "aud", "secret", allowedAlgs)
		if err != nil {
			return
		}

		// The "none" algorithm must never validate, even if an operator
		// mistakenly lists it in the allowlist.
		header := decodeJWTHeader(rawToken)
		if header == "none" || header == "" {
			t.Fatalf("algorithm %q was accepted; claims=%v", header, claims)
		}
	})
}

// FuzzFetchJWKSParse fuzzes the JWKS JSON decoding and key selection, which run
// on a document fetched from the identity provider.
func FuzzFetchJWKSParse(f *testing.F) {
	f.Add(`{"keys":[]}`, "kid", "RS256")
	f.Add(`{"keys":[{"kty":"RSA","kid":"rsa-1","alg":"RS256","n":"AQAB","e":"AQAB"}]}`, "rsa-1", "RS256")
	f.Add(`{"keys":null}`, "", "")
	f.Add(`{}`, "", "")
	f.Add(`[]`, "", "")
	f.Add(`{"keys":[{"kty":"EC","crv":"P-521","x":"","y":""}]}`, "", "ES512")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, doc, kid, alg string) {
		var jwks JWKS
		if err := json.Unmarshal([]byte(doc), &jwks); err != nil {
			return
		}

		// findKey and the compatibility check must tolerate any key shape the
		// provider sends, including empty or truncated coordinates.
		key, err := findKey(&jwks, kid, alg)
		if err != nil {
			return
		}
		if key == nil {
			t.Fatal("findKey returned no error but a nil key")
		}
		_ = isAlgCompatible(key, alg)

		// Reaching signature verification with attacker-shaped key material is
		// the interesting part: it must fail cleanly, never panic.
		_ = verifySignature(alg, key, []byte("signing-input"), []byte("signature"))
	})
}

// splitCSV splits a comma-separated list, trimming entries and dropping empties.
func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if part := s[start:i]; part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

// decodeJWTHeader returns the "alg" value of a JWT, or "" if it cannot be read.
func decodeJWTHeader(rawToken string) string {
	dot := -1
	for i := 0; i < len(rawToken); i++ {
		if rawToken[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return ""
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(rawToken[:dot])
	if err != nil {
		return ""
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return ""
	}
	return header.Alg
}
