# talosctl-oidc Helm Chart

A Helm chart for deploying the `talosctl-oidc` service, which provides an OIDC-based certificate exchange for Talos Linux clusters.

## Installation

```bash
helm install talosctl-oidc ./charts/talosctl-oidc --namespace talos-system --create-namespace
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `ghcr.io/qjoly/talosctl-oidc-server` |
| `image.tag` | Image tag | `latest` |
| `config.issuerUrl` | OIDC Issuer URL | `""` |
| `config.clientId` | OIDC Client ID | `""` |
| `config.clientSecret` | OIDC Client Secret (inline) | `""` |
| `config.existingSecret` | Existing secret name for `client-secret` and `admin-token` keys | `""` |
| `config.endpoints` | Talos node endpoints (list) | `[]` |
| `config.roles` | Talos roles to embed in issued certs | `["os:admin"]` |
| `config.certTTL` | Issued certificate TTL | `"1h"` |
| `config.adminToken` | Admin API bearer token (inline) | `""` |
| `config.auditLog` | Audit log destination (`-` = stdout) | `"-"` |
| `config.insecure` | Serve plain HTTP (no TLS) | `false` |
| `talos.apiAccess.enabled` | Create a `serviceaccounts.talos.dev` resource so Talos provisions the API credential | `true` |
| `talos.apiAccess.roles` | Roles for the server's own credential (bounds the certs it can issue) | `["os:admin"]` |
| `talos.configMountPath` | Mount path for the provisioned talosconfig | `/var/run/secrets/talos.dev` |
| `talos.existingCredentialSecret` | Use an existing talosconfig secret (`config` key) instead of creating the resource | `""` |

---

## Talos API access

The service issues certificates by calling the Talos API
(`GenerateClientConfiguration`), so it **never holds the cluster CA private
key**. The Talos node signs each certificate, and the roles the server can grant
are bounded by its own credential (Talos rejects privilege escalation).

### Prerequisite: enable the feature on the nodes

In the Talos machine config of the control plane nodes:

```yaml
machine:
  features:
    kubernetesTalosAPIAccess:
      enabled: true
      allowedRoles:
        - os:admin
      allowedKubernetesNamespaces:
        - talos-system   # the release namespace
```

### Mode A: Chart-managed credential (default)

With `talos.apiAccess.enabled=true`, the chart creates a
`serviceaccounts.talos.dev` resource. Talos provisions a short-lived talosconfig
into a secret that the pod mounts — no manual secret handling.

```yaml
talos:
  apiAccess:
    enabled: true
    roles:
      - os:admin
```

### Mode B: Existing credential secret

Provide a secret that already contains a talosconfig under the `config` key:

```yaml
talos:
  existingCredentialSecret: "my-talosconfig"
```

---

## OIDC Client Secret

### Option A: Existing Secret (Recommended)

```bash
kubectl create secret generic talosctl-oidc-config \
  --from-literal=client-secret="your-oidc-client-secret" \
  --from-literal=admin-token="optional-admin-token" \
  --namespace talos-system
```

```yaml
config:
  existingSecret: "talosctl-oidc-config"
```

### Option B: Inline Values

```yaml
config:
  clientSecret: "your-oidc-client-secret"
  adminToken: "optional-admin-token"
```
