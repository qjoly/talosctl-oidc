package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
