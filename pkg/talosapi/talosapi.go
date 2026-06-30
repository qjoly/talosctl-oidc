// Package talosapi issues short-lived client certificates by delegating to the
// Talos API (the GenerateClientConfiguration RPC) instead of holding the
// cluster CA private key.
//
// This is the secure issuing path. The server only needs a Talos API client
// credential — for example one provisioned in-cluster by the talos.dev/v1alpha1
// ServiceAccount (machine.features.kubernetesTalosAPIAccess) — and never the CA
// private key. The Talos node signs each certificate with the CA it already
// holds. The roles a server can grant are bounded by its own credential: Talos
// rejects any request for roles above the caller's own (verified: an os:reader
// credential cannot mint an os:admin certificate).
package talosapi

import (
	"context"
	"fmt"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ClientCertificate holds a generated ephemeral client certificate and key,
// plus the cluster CA certificate the client should trust.
type ClientCertificate struct {
	CertPEM []byte
	KeyPEM  []byte
	CaPEM   []byte
}

// Issuer issues client certificates via the Talos API.
type Issuer struct {
	// talosConfigPath is the path to the talosconfig used to authenticate to the
	// Talos API. When empty, the machinery default config is used (the in-cluster
	// ServiceAccount sets TALOSCONFIG to /var/run/secrets/talos.dev/config).
	talosConfigPath string
	endpoints       []string
}

// NewIssuer returns an Issuer authenticating with the given talosconfig path
// (may be empty to use the default/in-cluster config) and reaching the Talos
// API at the given node endpoints.
func NewIssuer(talosConfigPath string, endpoints []string) *Issuer {
	return &Issuer{talosConfigPath: talosConfigPath, endpoints: endpoints}
}

// Issue requests a new short-lived client certificate from the Talos API with
// the given roles and TTL.
func (i *Issuer) Issue(ctx context.Context, roles []string, ttl time.Duration) (*ClientCertificate, error) {
	// ponytail: open a fresh client per request. The ServiceAccount talosconfig
	// is short-lived and rotated on disk; reading it each time avoids a stale
	// cached credential. Pool per-endpoint if request volume ever makes this hurt.
	opts := []client.OptionFunc{}
	if i.talosConfigPath != "" {
		opts = append(opts, client.WithConfigFromFile(i.talosConfigPath))
	} else {
		opts = append(opts, client.WithDefaultConfig())
	}
	if len(i.endpoints) > 0 {
		opts = append(opts, client.WithEndpoints(i.endpoints...))
	}

	c, err := client.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating Talos API client: %w", err)
	}
	defer c.Close() //nolint:errcheck

	resp, err := c.GenerateClientConfiguration(ctx, &machine.GenerateClientConfigurationRequest{
		Roles:  roles,
		CrtTtl: durationpb.New(ttl),
	})
	if err != nil {
		return nil, fmt.Errorf("Talos GenerateClientConfiguration: %w", err)
	}

	msgs := resp.GetMessages()
	if len(msgs) == 0 {
		return nil, fmt.Errorf("Talos API returned no client configuration")
	}
	m := msgs[0]

	return &ClientCertificate{
		CertPEM: m.GetCrt(),
		KeyPEM:  m.GetKey(),
		CaPEM:   m.GetCa(),
	}, nil
}
