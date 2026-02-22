package certsign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
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

// LoadCAFromTalosConfig parses a talosconfig YAML file (as provisioned by the
// talos.dev/v1alpha1 ServiceAccount at /var/run/secrets/talos.dev/config) and
// extracts the CA certificate and issuing private key from the default context.
//
// The talosconfig format stores the CA cert under the "ca" key and the issuing
// key under the "key" key, both as base64-encoded PEM.
func LoadCAFromTalosConfig(configPath string) (*CA, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading talosconfig: %w", err)
	}

	// Minimal line-by-line parser: find "ca:" and "key:" inside the active context.
	// We avoid pulling in a full YAML library to keep dependencies minimal.
	certB64, keyB64, err := parseTalosConfigFields(data)
	if err != nil {
		return nil, err
	}

	certPEM, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, fmt.Errorf("decoding talosconfig ca field: %w", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decoding talosconfig key field: %w", err)
	}

	return ParseCA(certPEM, keyPEM)
}

// parseTalosConfigFields extracts the base64-encoded "ca" and "key" values
// from the active context found in a talosconfig YAML byte slice.
func parseTalosConfigFields(data []byte) (ca, key string, err error) {
	lines := strings.Split(string(data), "\n")

	var activeContext string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "context:") {
			activeContext = strings.TrimSpace(strings.TrimPrefix(trimmed, "context:"))
			break
		}
	}

	var caVal, keyVal strings.Builder
	var currentField string
	var inTargetContext bool
	var contextIndentation int

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := 0
		for i, r := range line {
			if r != ' ' && r != '\t' {
				indent = i
				break
			}
		}

		// Detect context start
		if activeContext != "" && strings.HasPrefix(trimmed, activeContext+":") {
			inTargetContext = true
			contextIndentation = indent
			continue
		}

		// If we are in the target context, look for ca/key
		if inTargetContext {
			// If we hit a new key at the same or lower indentation, we left the context
			if indent <= contextIndentation && !strings.HasPrefix(trimmed, activeContext+":") && !strings.HasPrefix(trimmed, "ca:") && !strings.HasPrefix(trimmed, "key:") {
				if caVal.Len() > 0 && keyVal.Len() > 0 {
					break // Found our pair
				}
				inTargetContext = false
			}

			for _, field := range []string{"ca", "key"} {
				prefix := field + ":"
				if strings.HasPrefix(trimmed, prefix) {
					val := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
					currentField = field
					switch field {
					case "ca":
						caVal.Reset()
						caVal.WriteString(val)
					case "key":
						keyVal.Reset()
						keyVal.WriteString(val)
					}
					goto nextLine
				}
			}

			// Continuation lines
			if currentField != "" && indent > 0 && !strings.Contains(trimmed, ":") {
				switch currentField {
				case "ca":
					caVal.WriteString(trimmed)
				case "key":
					keyVal.WriteString(trimmed)
				}
			}
		} else if activeContext == "" {
			// Fallback: take the first ca/key we find if no context is specified
			for _, field := range []string{"ca", "key"} {
				prefix := field + ":"
				if strings.HasPrefix(trimmed, prefix) {
					val := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
					currentField = field
					switch field {
					case "ca":
						if caVal.Len() == 0 {
							caVal.WriteString(val)
						} else {
							currentField = "" // Don't append to previous ca
						}
					case "key":
						if keyVal.Len() == 0 {
							keyVal.WriteString(val)
						} else {
							currentField = ""
						}
					}
					goto nextLine
				}
			}
			if currentField != "" && indent > 0 && !strings.Contains(trimmed, ":") {
				switch currentField {
				case "ca":
					if caVal.Len() < 10000 { // Safety limit for fallback
						caVal.WriteString(trimmed)
					}
				case "key":
					if keyVal.Len() < 10000 {
						keyVal.WriteString(trimmed)
					}
				}
			}
		}
	nextLine:
	}

	if caVal.Len() == 0 {
		return "", "", fmt.Errorf("talosconfig: 'ca' field not found for context '%s'", activeContext)
	}
	if keyVal.Len() == 0 {
		return "", "", fmt.Errorf("talosconfig: 'key' field not found for context '%s'", activeContext)
	}

	return caVal.String(), keyVal.String(), nil
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
