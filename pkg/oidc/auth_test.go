package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// freePort grabs a port the OS just handed out, then releases it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestCallbackServerListensOnEveryAddress(t *testing.T) {
	addrs := []string{
		fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		fmt.Sprintf("127.0.0.1:%d", freePort(t)),
	}

	cs, err := NewCallbackServer(AuthConfig{ListenAddresses: addrs})
	if err != nil {
		t.Fatalf("NewCallbackServer: %v", err)
	}
	cs.Start()
	defer cs.Shutdown(context.Background())

	if want := "http://" + addrs[0] + "/callback"; cs.RedirectURI() != want {
		t.Errorf("RedirectURI() = %q, want %q", cs.RedirectURI(), want)
	}

	// The callback must be answered on the second address too, not only the first.
	resp, err := http.Get("http://" + addrs[1] + "/callback?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("calling second listener: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := cs.WaitForCallback(ctx)
	if err != nil {
		t.Fatalf("WaitForCallback: %v", err)
	}
	if result.Code != "abc" || result.State != "xyz" {
		t.Errorf("got code=%q state=%q, want code=abc state=xyz", result.Code, result.State)
	}
}

func TestCallbackServerRejectsEmptyAddressList(t *testing.T) {
	if _, err := NewCallbackServer(AuthConfig{}); err == nil {
		t.Fatal("expected an error with no listen address")
	}
}

func TestCallbackServerReleasesListenersOnBindFailure(t *testing.T) {
	good := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	if _, err := NewCallbackServer(AuthConfig{ListenAddresses: []string{good, "127.0.0.1:not-a-port"}}); err == nil {
		t.Fatal("expected a bind error")
	}

	// The first port must be free again, otherwise a retry would fail.
	l, err := net.Listen("tcp", good)
	if err != nil {
		t.Fatalf("port %s left bound after a failed bind: %v", good, err)
	}
	l.Close()
}

// selfSignedPair writes a throwaway cert/key valid for 127.0.0.1 and returns their paths.
func selfSignedPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)

	return certPath, keyPath
}

func TestCallbackServerServesTLSAndAdvertisesHTTPS(t *testing.T) {
	certPath, keyPath := selfSignedPair(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	cs, err := NewCallbackServer(AuthConfig{
		ListenAddresses: []string{addr},
		TLSCertFile:     certPath,
		TLSKeyFile:      keyPath,
	})
	if err != nil {
		t.Fatalf("NewCallbackServer: %v", err)
	}
	cs.Start()
	defer cs.Shutdown(context.Background())

	if want := "https://" + addr + "/callback"; cs.RedirectURI() != want {
		t.Errorf("RedirectURI() = %q, want %q", cs.RedirectURI(), want)
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test cert
	}}
	resp, err := client.Get("https://" + addr + "/callback?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("calling HTTPS callback: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := cs.WaitForCallback(ctx)
	if err != nil {
		t.Fatalf("WaitForCallback: %v", err)
	}
	if result.Code != "abc" {
		t.Errorf("code = %q, want abc", result.Code)
	}
}

func TestCallbackServerRejectsHalfTLSPair(t *testing.T) {
	certPath, _ := selfSignedPair(t)

	if _, err := NewCallbackServer(AuthConfig{
		ListenAddresses: []string{fmt.Sprintf("127.0.0.1:%d", freePort(t))},
		TLSCertFile:     certPath,
	}); err == nil {
		t.Fatal("expected an error when only the certificate is given")
	}
}

func TestCallbackServerUsesCustomRedirectURL(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	redirect := "https://talos.example.com:8900/oidc/cb"

	cs, err := NewCallbackServer(AuthConfig{
		ListenAddresses: []string{addr},
		RedirectURL:     redirect,
	})
	if err != nil {
		t.Fatalf("NewCallbackServer: %v", err)
	}
	cs.Start()
	defer cs.Shutdown(context.Background())

	if cs.RedirectURI() != redirect {
		t.Errorf("RedirectURI() = %q, want %q", cs.RedirectURI(), redirect)
	}

	// The provider redirects to the custom path, so the server must answer there.
	resp, err := http.Get("http://" + addr + "/oidc/cb?code=abc&state=xyz")
	if err != nil {
		t.Fatalf("calling custom callback path: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cs.WaitForCallback(ctx); err != nil {
		t.Fatalf("WaitForCallback: %v", err)
	}
}

func TestCallbackServerRejectsRelativeRedirectURL(t *testing.T) {
	if _, err := NewCallbackServer(AuthConfig{
		ListenAddresses: []string{fmt.Sprintf("127.0.0.1:%d", freePort(t))},
		RedirectURL:     "/callback",
	}); err == nil {
		t.Fatal("expected an error for a relative redirect URL")
	}
}

// TestAuthenticateUsesConfiguredRedirectURI walks the whole code flow against a
// fake provider: the URI must be identical in the authorization request and in
// the token exchange, which is what strict providers check.
func TestAuthenticateUsesConfiguredRedirectURI(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	redirect := "http://" + addr + "/oidc/cb"

	var tokenRedirect string
	mux := http.NewServeMux()
	provider := httptest.NewServer(mux)
	defer provider.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q}`,
			provider.URL, provider.URL+"/auth", provider.URL+"/token")
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		tokenRedirect = r.FormValue("redirect_uri")
		fmt.Fprint(w, `{"access_token":"at","id_token":"it","refresh_token":"rt","expires_in":3600}`)
	})

	var authRedirect string
	openBrowser := func(rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			return err
		}
		authRedirect = u.Query().Get("redirect_uri")

		// Play the provider: bounce the browser back to the callback.
		resp, err := http.Get(fmt.Sprintf("%s?code=the-code&state=%s", authRedirect, u.Query().Get("state")))
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := Authenticate(ctx, AuthConfig{
		IssuerURL:       provider.URL,
		ClientID:        "talosctl-oidc",
		ListenAddresses: []string{addr},
		RedirectURL:     redirect,
		OpenBrowser:     openBrowser,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if token.IDToken != "it" {
		t.Errorf("IDToken = %q, want it", token.IDToken)
	}
	if authRedirect != redirect {
		t.Errorf("authorization redirect_uri = %q, want %q", authRedirect, redirect)
	}
	if tokenRedirect != redirect {
		t.Errorf("token redirect_uri = %q, want %q", tokenRedirect, redirect)
	}
}
