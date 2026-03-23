package certsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCA(t *testing.T) (*CA, []byte, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	ca, err := ParseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsing CA: %v", err)
	}
	return ca, certPEM, keyPEM
}

func TestGenerateClientCert_TTL(t *testing.T) {
	ca, _, _ := generateTestCA(t)
	ttl := time.Hour

	cert, err := GenerateClientCert(ca, []string{"os:admin"}, ttl)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	block, _ := pem.Decode(cert.CertPEM)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	actualTTL := parsed.NotAfter.Sub(parsed.NotBefore)
	// Allow a small tolerance for test execution time
	if actualTTL < ttl-5*time.Second || actualTTL > ttl+5*time.Second {
		t.Errorf("expected TTL ~%v, got %v", ttl, actualTTL)
	}
}

func TestGenerateClientCert_Roles(t *testing.T) {
	ca, _, _ := generateTestCA(t)
	roles := []string{"os:admin", "os:operator"}
	cert, err := GenerateClientCert(ca, roles, time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	block, _ := pem.Decode(cert.CertPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)
	if len(parsed.Subject.Organization) != len(roles) {
		t.Errorf("expected %d org entries, got %d", len(roles), len(parsed.Subject.Organization))
	}
	for i, role := range roles {
		if parsed.Subject.Organization[i] != role {
			t.Errorf("expected org[%d] = %q, got %q", i, role, parsed.Subject.Organization[i])
		}
	}
}

func TestGenerateClientCert_SignedByCA(t *testing.T) {
	ca, certPEM, _ := generateTestCA(t)
	cert, err := GenerateClientCert(ca, []string{"os:reader"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Build a cert pool with the CA cert
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add CA cert to pool")
	}

	block, _ := pem.Decode(cert.CertPEM)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing client cert: %v", err)
	}

	_, err = parsed.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("client cert verification failed: %v", err)
	}
}

func TestGenerateClientCert_NotCA(t *testing.T) {
	ca, _, _ := generateTestCA(t)
	cert, err := GenerateClientCert(ca, []string{"os:admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	block, _ := pem.Decode(cert.CertPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)
	if parsed.IsCA {
		t.Error("client certificate should not be a CA")
	}
}

func TestGenerateClientCert_KeyUsageClientAuth(t *testing.T) {
	ca, _, _ := generateTestCA(t)
	cert, err := GenerateClientCert(ca, []string{"os:admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	block, _ := pem.Decode(cert.CertPEM)
	parsed, _ := x509.ParseCertificate(block.Bytes)

	hasClientAuth := false
	for _, eku := range parsed.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Error("client certificate should have ExtKeyUsageClientAuth")
	}
}

func TestGenerateClientCert_CAPEMIncluded(t *testing.T) {
	ca, certPEM, _ := generateTestCA(t)
	cert, err := GenerateClientCert(ca, []string{"os:admin"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}
	if string(cert.CaPEM) != string(certPEM) {
		t.Error("CA PEM in ClientCertificate does not match original CA cert PEM")
	}
}

func TestParseCA_MismatchedKeyAndCert(t *testing.T) {
	// Generate two different key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key1: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key2: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create a self-signed cert with key pair 1
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub1, priv1)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Use priv2 (a different key) — cert has pub1 but we supply priv2
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv2)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	_, err = ParseCA(certPEM, keyPEM)
	if err == nil {
		t.Error("expected error for mismatched CA cert and key")
	}
}
