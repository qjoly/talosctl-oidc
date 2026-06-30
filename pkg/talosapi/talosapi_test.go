package talosapi

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/qjoly/talosctl-oidc/internal/mocktalos"
)

// TestIssue_AgainstMockTalosAPI exercises the full issuing path: build a Talos
// API client from a talosconfig, connect over mTLS to a fake Talos node, call
// GenerateClientConfiguration, and verify the returned certificate carries the
// requested roles and TTL. This is the unit-level counterpart of the CI
// integration test and needs no real cluster.
func TestIssue_AgainstMockTalosAPI(t *testing.T) {
	mock, err := mocktalos.New()
	if err != nil {
		t.Fatalf("creating mock: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	endpoint := lis.Addr().String() // 127.0.0.1:<random port>

	grpcSrv := mock.GRPCServer()
	go grpcSrv.Serve(lis) //nolint:errcheck
	t.Cleanup(grpcSrv.Stop)

	tcPath := filepath.Join(t.TempDir(), "talosconfig")
	if err := mock.WriteTalosconfig(tcPath, endpoint); err != nil {
		t.Fatalf("writing talosconfig: %v", err)
	}

	// Endpoints passed explicitly carry the random port; the talosconfig host
	// (127.0.0.1) matches the server certificate SAN.
	issuer := NewIssuer(tcPath, []string{endpoint})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cert, err := issuer.Issue(ctx, []string{"os:reader"}, 7*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if len(cert.CaPEM) == 0 || len(cert.CertPEM) == 0 || len(cert.KeyPEM) == 0 {
		t.Fatal("Issue returned empty PEM material")
	}

	block, _ := pem.Decode(cert.CertPEM)
	if block == nil {
		t.Fatal("returned cert is not valid PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing returned cert: %v", err)
	}

	if got := parsed.Subject.Organization; len(got) != 1 || got[0] != "os:reader" {
		t.Errorf("cert roles (Organization) = %v, want [os:reader]", got)
	}

	ttl := parsed.NotAfter.Sub(parsed.NotBefore)
	if ttl < 6*time.Minute || ttl > 8*time.Minute {
		t.Errorf("cert TTL = %v, want ~7m", ttl)
	}
}
