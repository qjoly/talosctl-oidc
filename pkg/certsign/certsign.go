package certsign

import (
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
// from the first context block found in a talosconfig YAML byte slice.
// It handles multi-line base64 values (indented continuation lines).
func parseTalosConfigFields(data []byte) (ca, key string, err error) {
	lines := strings.Split(string(data), "\n")

	var caVal, keyVal strings.Builder
	var currentField string // "ca" or "key"

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect field start: "ca: <value>" or "key: <value>"
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

		// Continuation of a multi-line base64 value: indented and no colon key.
		if currentField != "" && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && !strings.Contains(trimmed, ":") {
			switch currentField {
			case "ca":
				caVal.WriteString(trimmed)
			case "key":
				keyVal.WriteString(trimmed)
			}
		} else if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Top-level key: reset continuation tracking unless it's a known field.
			if trimmed != "" && !strings.HasPrefix(trimmed, "ca:") && !strings.HasPrefix(trimmed, "key:") {
				currentField = ""
			}
		}

	nextLine:
	}

	if caVal.Len() == 0 {
		return "", "", fmt.Errorf("talosconfig: 'ca' field not found")
	}
	if keyVal.Len() == 0 {
		return "", "", fmt.Errorf("talosconfig: 'key' field not found")
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
