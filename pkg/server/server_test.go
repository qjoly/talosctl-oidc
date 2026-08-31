package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestServer builds a minimal Server suitable for exercising the plain
// HTTP handlers (/healthz, /ca) that need no OIDC, Talos, or admin wiring.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return New(Config{ListenAddr: ":8080"})
}

// TestHandleHealthMethodGuard verifies that /healthz answers GET and rejects
// every other method with 405 Method Not Allowed (issue #44).
func TestHandleHealthMethodGuard(t *testing.T) {
	srv := newTestServer(t)

	t.Run("GET returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+" returns 405", func(t *testing.T) {
			req := httptest.NewRequest(method, "/healthz", nil)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
			}
		})
	}
}

// TestHandleCAMethodGuard verifies that /ca answers GET and rejects every
// other method with 405 Method Not Allowed (issue #44).
//
// The method guard must run before the self-signed-mode check, so a rejected
// method returns 405 regardless of whether a CA is configured.
func TestHandleCAMethodGuard(t *testing.T) {
	srv := newTestServer(t)
	// Same package: set the unexported CA PEM directly so /ca has content to
	// serve on the happy path.
	srv.selfSignedCAPEM = []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

	t.Run("GET returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ca", nil)
		rec := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
	})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+" returns 405", func(t *testing.T) {
			req := httptest.NewRequest(method, "/ca", nil)
			rec := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
			}
		})
	}
}

// TestLoadPersistedSelfSignedTLSRegeneratesExpired checks that an expired
// persisted certificate is replaced instead of served (issue #38).
func TestLoadPersistedSelfSignedTLSRegeneratesExpired(t *testing.T) {
	dir := t.TempDir()
	srv := New(Config{ListenAddr: ":8080", DataDir: dir})

	// First call populates the data directory with valid material.
	if _, err := srv.loadOrGenerateSelfSignedTLS(); err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// Overwrite the server key pair with an already-expired one.
	srvCrtPath, srvKeyPath := writeExpiredKeyPair(t, dir)

	if _, err := srv.loadPersistedSelfSignedTLS(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), srvCrtPath, srvKeyPath); !errors.Is(err, errCertExpired) {
		t.Fatalf("expected errCertExpired, got %v", err)
	}

	tlsCfg, err := srv.loadOrGenerateSelfSignedTLS()
	if err != nil {
		t.Fatalf("regeneration failed: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parsing regenerated certificate: %v", err)
	}
	if time.Now().After(leaf.NotAfter) {
		t.Fatalf("regenerated certificate is already expired (NotAfter %s)", leaf.NotAfter)
	}
}

// writeExpiredKeyPair writes an expired self-signed key pair to dir as
// server.crt / server.key.
func writeExpiredKeyPair(t *testing.T, dir string) (crtPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}

	crtPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	return crtPath, keyPath
}
