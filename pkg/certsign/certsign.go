package certsign

import (
	"bytes"
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
// The CA key file is loaded via LoadCAKeyFromFile, which enforces strict
// file permission requirements (0400 or 0600) per ISO 27001 A.10.1.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	keyPEM, err := LoadCAKeyFromFile(keyPath)
	if err != nil {
		return nil, err
	}

	return ParseCA(certPEM, keyPEM)
}

// LoadCAKeyFromFile loads a CA private key from a file, verifying it has
// restrictive permissions (owner read-only: 0400 or 0600).
//
// Passing private key material through environment variables exposes it via
// /proc/<pid>/environ and shell history. Loading from a file with strict
// permissions is preferred (ISO 27001 A.10.1 — cryptographic key management).
func LoadCAKeyFromFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat CA key file: %w", err)
	}

	// Check permissions: only allow 0400 or 0600.
	mode := info.Mode().Perm()
	if mode != 0o400 && mode != 0o600 {
		return nil, fmt.Errorf("CA key file %s has insecure permissions %04o; require 0400 or 0600", path, mode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA key file: %w", err)
	}
	return data, nil
}

// LoadCAFromTalosConfig parses a talosconfig YAML file (as provisioned by the
// talos.dev/v1alpha1 ServiceAccount at /var/run/secrets/talos.dev/config) and
// extracts the CA certificate and issuing private key from the default context.
//
// The talosconfig provisioned by the Talos ServiceAccount contains three fields
// under the active context:
//
//	ca  — the cluster CA certificate (base64-encoded PEM)
//	crt — a client certificate signed by the CA (base64-encoded PEM)
//	key — the client's private key (base64-encoded PEM)
//
// This server needs to *sign* new client certificates, which requires the CA
// private key. The talos.dev ServiceAccount does NOT provision the CA private
// key. Therefore this function returns a clear error rather than silently
// loading a mismatched ca cert + client key pair.
//
// To run this server you must supply the Talos CA certificate and its private
// key via one of the other mechanisms (TALOSCTL_OIDC_CA_CERT_DATA /
// TALOSCTL_OIDC_CA_KEY_DATA env vars, or TALOSCTL_OIDC_CA_CERT /
// TALOSCTL_OIDC_CA_KEY file paths).
func LoadCAFromTalosConfig(_ string) (*CA, error) {
	return nil, fmt.Errorf(
		"the talos.dev/v1alpha1 ServiceAccount (apiAccess) only provisions a client " +
			"certificate and key, not the CA private key required to sign new certificates. " +
			"Disable talos.apiAccess.enabled and supply the Talos CA cert and key directly " +
			"via TALOSCTL_OIDC_CA_CERT_DATA / TALOSCTL_OIDC_CA_KEY_DATA (or the file-path " +
			"equivalents TALOSCTL_OIDC_CA_CERT / TALOSCTL_OIDC_CA_KEY)",
	)
}

// ParseCA parses PEM-encoded CA certificate and private key bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	var cert *x509.Certificate

	rest := certPEM
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing CA certificate: %w", err)
			}
			if c.IsCA {
				cert = c
				break
			}
			if cert == nil {
				cert = c
			}
		}
		rest = remaining
	}

	if cert == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	var keyBlock *pem.Block
	keyRest := keyPEM
	for len(keyRest) > 0 {
		block, remaining := pem.Decode(keyRest)
		if block == nil {
			break
		}
		if block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" || block.Type == "ED25519 PRIVATE KEY" {
			keyBlock = block
			break
		}
		keyRest = remaining
	}

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

	// Validate that the private key matches the certificate's public key.
	// x509.CreateCertificate enforces this too, but catching it here at load
	// time gives a much clearer error message than "PrivateKey doesn't match
	// parent's PublicKey" surfacing on the first certificate request.
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA certificate public key: %w", err)
	}
	signerPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshaling CA private key's public key: %w", err)
	}
	if !bytes.Equal(certPubDER, signerPubDER) {
		return nil, fmt.Errorf("CA private key does not match CA certificate public key: the cert and key are from different key pairs")
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

const (
	minCertTTL = 5 * time.Minute
	maxCertTTL = 24 * time.Hour
)

// GenerateClientCert creates a short-lived client certificate signed by the Talos CA.
// The certificate Organization field is set to the provided roles (e.g. "os:admin"),
// matching the Talos RBAC convention.
func GenerateClientCert(ca *CA, roles []string, ttl time.Duration) (*ClientCertificate, error) {
	// Clamp TTL to safe bounds.
	if ttl < minCertTTL {
		ttl = minCertTTL
	}
	if ttl > maxCertTTL {
		ttl = maxCertTTL
	}

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
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return &ClientCertificate{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CaPEM:   ca.CertPEM,
	}, nil
}
