// Package mocktalos is a minimal fake Talos API server for tests. It implements
// only the GenerateClientConfiguration RPC: given roles and a TTL it returns a
// freshly signed client certificate, like a real Talos node would, signed by a
// throwaway CA generated at construction time. It also produces a talosconfig
// (client credential) so callers can authenticate over mTLS, mirroring how the
// talosctl-oidc server talks to a real Talos API.
//
// It is used both by the hack/mock-talos-api binary and by the talosapi tests.
package mocktalos

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server is a fake Talos API server with its own throwaway CA.
type Server struct {
	machine.UnimplementedMachineServiceServer

	caCert    *x509.Certificate
	caKey     ed25519.PrivateKey
	caPEM     []byte
	tlsCert   tls.Certificate
	clientCrt []byte
	clientKey []byte
}

// New generates the CA, a server TLS certificate valid for 127.0.0.1/localhost,
// and an admin client certificate for the talosconfig.
func New() (*Server, error) {
	caCert, caKey, caPEM, err := genCA()
	if err != nil {
		return nil, err
	}
	s := &Server{caCert: caCert, caKey: caKey, caPEM: caPEM}

	srvCrt, srvKey, err := s.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "mock-talos-api"},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	})
	if err != nil {
		return nil, err
	}
	s.tlsCert, err = tls.X509KeyPair(srvCrt, srvKey)
	if err != nil {
		return nil, err
	}

	s.clientCrt, s.clientKey, err = s.issue(&x509.Certificate{
		Subject:     pkix.Name{Organization: []string{"os:admin"}},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, err
	}

	return s, nil
}

func genCA() (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"talos"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return caCert, priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// issue signs a leaf certificate, returning cert and key PEM.
func (s *Server) issue(tmpl *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, pub, s.caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// GenerateClientConfiguration mints a short-lived client certificate with the
// requested roles, like a real Talos node.
func (s *Server) GenerateClientConfiguration(_ context.Context, req *machine.GenerateClientConfigurationRequest) (*machine.GenerateClientConfigurationResponse, error) {
	ttl := req.GetCrtTtl().AsDuration()
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	crt, key, err := s.issue(&x509.Certificate{
		Subject:     pkix.Name{Organization: req.GetRoles()},
		NotBefore:   now,
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, err
	}
	return &machine.GenerateClientConfigurationResponse{
		Messages: []*machine.GenerateClientConfiguration{{Ca: s.caPEM, Crt: crt, Key: key}},
	}, nil
}

// GRPCServer returns a gRPC server with mTLS configured, ready to Serve.
func (s *Server) GRPCServer() *grpc.Server {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})
	g := grpc.NewServer(grpc.Creds(creds))
	machine.RegisterMachineServiceServer(g, s)
	return g
}

// TalosconfigYAML returns a talosconfig pointing at the given endpoint, with the
// admin client credential for mTLS.
func (s *Server) TalosconfigYAML(endpoint string) []byte {
	b64 := base64.StdEncoding.EncodeToString
	return []byte(fmt.Sprintf(`context: mock
contexts:
    mock:
        endpoints:
            - %s
        ca: %s
        crt: %s
        key: %s
`, endpoint, b64(s.caPEM), b64(s.clientCrt), b64(s.clientKey)))
}

// WriteTalosconfig writes the talosconfig to path.
func (s *Server) WriteTalosconfig(path, endpoint string) error {
	return os.WriteFile(path, s.TalosconfigYAML(endpoint), 0o600)
}
