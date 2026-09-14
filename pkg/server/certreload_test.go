package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair generates a self-signed certificate for cn and writes it to
// certPath/keyPath, returning the certificate's serial number so tests can tell
// two generations apart.
func writeKeyPair(t *testing.T, certPath, keyPath, cn string) *big.Int {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	return serial
}

// leafSerial returns the serial of the certificate currently served.
func leafSerial(t *testing.T, cert *tls.Certificate) *big.Int {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing served certificate: %v", err)
	}
	return leaf.SerialNumber
}

func TestCertReloader_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := newCertReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), time.Minute)
	if err == nil {
		t.Fatal("expected an error when the keypair does not exist")
	}
}

func TestCertReloader_ServesInitialCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	want := writeKeyPair(t, certPath, keyPath, "first.example.com")

	r, err := newCertReloader(certPath, keyPath, time.Minute)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if leafSerial(t, got).Cmp(want) != 0 {
		t.Fatalf("served the wrong certificate: got serial %v, want %v", leafSerial(t, got), want)
	}
}

// The rotation case this whole type exists for: cert-manager rewrites the
// mounted Secret and the server must start serving the new certificate.
func TestCertReloader_PicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	first := writeKeyPair(t, certPath, keyPath, "first.example.com")

	// interval 0 so every call re-stats, rather than sleeping in the test.
	r, err := newCertReloader(certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	got, _ := r.GetCertificate(nil)
	if leafSerial(t, got).Cmp(first) != 0 {
		t.Fatal("did not serve the initial certificate")
	}

	second := writeKeyPair(t, certPath, keyPath, "second.example.com")
	if first.Cmp(second) == 0 {
		t.Fatal("test bug: both generations share a serial")
	}

	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after rotation: %v", err)
	}
	if leafSerial(t, got).Cmp(second) != 0 {
		t.Fatalf("stale certificate after rotation: got serial %v, want %v", leafSerial(t, got), second)
	}
}

// Within the check interval the files must not be re-read, so the handshake
// path stays off the filesystem.
func TestCertReloader_HonoursInterval(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	first := writeKeyPair(t, certPath, keyPath, "first.example.com")

	r, err := newCertReloader(certPath, keyPath, time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	writeKeyPair(t, certPath, keyPath, "second.example.com")

	got, _ := r.GetCertificate(nil)
	if leafSerial(t, got).Cmp(first) != 0 {
		t.Fatal("reloaded before the interval elapsed")
	}
}

// A broken or half-written keypair must not break TLS: the last good
// certificate keeps being served.
func TestCertReloader_KeepsLastGoodCertificateOnError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	first := writeKeyPair(t, certPath, keyPath, "first.example.com")

	r, err := newCertReloader(certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	// Truncated PEM, as seen mid-write.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nbroken\n"), 0o600); err != nil {
		t.Fatalf("corrupting certificate: %v", err)
	}

	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate must not fail on a bad reload: %v", err)
	}
	if leafSerial(t, got).Cmp(first) != 0 {
		t.Fatal("did not keep serving the last good certificate")
	}

	// Deleting the files entirely must behave the same way.
	os.Remove(certPath)
	os.Remove(keyPath)

	got, err = r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate must not fail when the files vanish: %v", err)
	}
	if leafSerial(t, got).Cmp(first) != 0 {
		t.Fatal("did not keep serving the last good certificate after deletion")
	}
}

// A rotation must be visible through a real handshake, not just through the
// callback, since that is how the certificate actually reaches a client.
func TestCertReloader_RotationVisibleOverTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeKeyPair(t, certPath, keyPath, "first.example.com")

	r, err := newCertReloader(certPath, keyPath, 0)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	serverConf := r.tlsConfig()
	if serverConf.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 floor, got %x", serverConf.MinVersion)
	}

	handshakeCN := func() string {
		t.Helper()
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			_ = tls.Server(serverConn, serverConf).Handshake()
		}()

		client := tls.Client(clientConn, &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- test asserts on the presented certificate, not on trust
			ServerName:         "example.com",
		})
		if err := client.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return client.ConnectionState().PeerCertificates[0].Subject.CommonName
	}

	if cn := handshakeCN(); cn != "first.example.com" {
		t.Fatalf("expected first.example.com, got %s", cn)
	}

	writeKeyPair(t, certPath, keyPath, "second.example.com")

	if cn := handshakeCN(); cn != "second.example.com" {
		t.Fatalf("rotation not visible over TLS: got %s", cn)
	}
}
