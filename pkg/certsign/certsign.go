package certsign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CA holds the parsed Talos CA certificate and private key.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
}

// LoadCA reads a PEM-encoded CA certificate and private key from files.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA private key: %w", err)
	}

	return ParseCA(certPEM, keyPEM)
}

// ParseCA parses PEM-encoded CA certificate and private key bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA private key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  signer,
		CertPEM:     certPEM,
	}, nil
}

// ClientCertificate holds the generated ephemeral client certificate and key.
type ClientCertificate struct {
	CertPEM []byte
	KeyPEM  []byte
	CaPEM   []byte
}

// GenerateClientCert creates a short-lived client certificate signed by the Talos CA.
// The certificate Organization field is set to the provided roles (e.g. "os:admin"),
// matching the Talos RBAC convention.
func GenerateClientCert(ca *CA, roles []string, ttl time.Duration) (*ClientCertificate, error) {
	// Generate a new Ed25519 key pair for the client.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating client key: %w", err)
	}

	// Generate a random serial number.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: roles,
		},
		NotBefore:             now,
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	// Sign the client certificate with the CA.
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, pubKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("signing client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Marshal the private key to PKCS8 PEM.
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling client private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return &ClientCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CaPEM:   ca.CertPEM,
	}, nil
}
