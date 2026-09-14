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
| `tls.existingSecret` | Existing Secret with `tls.crt`/`tls.key` for the pod to serve | `""` |
| `tls.mountPath` | Where the keypair is mounted in the container | `/tls` |
| `tls.certManager.enabled` | Create a cert-manager `Certificate` for the pod's TLS | `false` |
| `tls.certManager.issuerName` | Issuer/ClusterIssuer name (required when enabled) | `""` |
| `tls.certManager.issuerKind` | `Issuer` or `ClusterIssuer` | `ClusterIssuer` |
| `tls.certManager.commonName` | Optional CommonName override | `""` |
| `tls.certManager.dnsNames` | Certificate SANs; derived from the ingress hosts or Service names when empty | `[]` |
| `tls.certManager.duration` | Certificate lifetime | `"2160h"` |
| `tls.certManager.renewBefore` | Renew this long before expiry | `"360h"` |
| `tls.certManager.privateKey` | Optional cert-manager `privateKey` block | `{}` |
| `ingress.sslPassthrough` | Let the pod terminate TLS instead of the controller | `false` |
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

## Server TLS

By default the pod generates a self-signed certificate at startup, and clients must be pointed at its CA (`talosctl-oidc login --server-ca`). There are three alternatives.

### Terminate TLS at the ingress (simplest)

Set `ingress.enabled=true` with `ingress.tls`, and the chart switches the pod to plain HTTP — the controller holds the certificate.

```bash
helm install talosctl-oidc oci://ghcr.io/qjoly/charts/talosctl-oidc \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=talos.example.com \
  --set ingress.tls[0].secretName=talos-example-tls \
  --set ingress.tls[0].hosts[0]=talos.example.com
```

Clients see the controller's certificate, so nothing extra is needed if it is publicly trusted.

### Give the pod a cert-manager certificate

```bash
helm install talosctl-oidc oci://ghcr.io/qjoly/charts/talosctl-oidc \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerName=internal-ca \
  --set tls.certManager.issuerKind=ClusterIssuer
```

The chart creates a `Certificate`, mounts the resulting Secret at `/tls`, and points `TALOSCTL_OIDC_TLS_CERT`/`TALOSCTL_OIDC_TLS_KEY` at it. cert-manager must already be installed: the chart does not check for the CRD, so that `helm template` and GitOps rendering keep working without cluster access.

SANs are derived when `dnsNames` is empty — the ingress hosts if an ingress is enabled, otherwise the in-cluster Service names. The two sets are deliberately not merged, because a public ACME issuer cannot validate a `.svc.cluster.local` name and would reject the whole certificate. Set `dnsNames` explicitly to cover both.

**Renewals do not need a restart.** The server re-reads the keypair when it changes, so a rotated Secret is picked up within a minute.

### Bring your own Secret

```bash
helm install talosctl-oidc oci://ghcr.io/qjoly/charts/talosctl-oidc \
  --set tls.existingSecret=my-tls
```

The Secret must contain `tls.crt` and `tls.key`. This takes precedence over `tls.certManager`.

### SSL passthrough

With normal ingress termination the client only ever sees the controller's certificate. If clients need to verify the server end to end, enable passthrough so the encrypted stream reaches the pod:

```bash
helm install talosctl-oidc oci://ghcr.io/qjoly/charts/talosctl-oidc \
  --set ingress.enabled=true \
  --set ingress.sslPassthrough=true \
  --set ingress.hosts[0].host=talos.example.com \
  --set-string 'ingress.annotations.nginx\.ingress\.kubernetes\.io/ssl-passthrough=true' \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerName=internal-ca
```

Three things are required, and the chart can only do the first:

1. `ingress.sslPassthrough=true`, which keeps the pod on HTTPS and drops the `tls` block from the Ingress.
2. The controller-specific annotation, which the chart cannot infer:

   | Controller | Annotation |
   |---|---|
   | ingress-nginx | `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` |
   | Traefik | `traefik.ingress.kubernetes.io/router.tls.passthrough: "true"` |
   | HAProxy | `haproxy.org/ssl-passthrough: "true"` |

3. Passthrough enabled globally on the controller (ingress-nginx: `--enable-ssl-passthrough`).

The chart warns at install time if `sslPassthrough` is set without a matching annotation, since that combination fails in a confusing way: the controller terminates TLS while the pod also expects to.

### Behaviour summary

| `ingress.tls` | `sslPassthrough` | cert source | Pod | Ingress |
|---|---|---|---|---|
| — | — | no | self-signed | — |
| — | — | yes | provided cert | — |
| set | false | no | **plain HTTP** | terminates |
| set | false | yes | provided cert | terminates (re-encrypt) |
| — | true | no | self-signed | passthrough |
| — | true | yes | provided cert | passthrough |

Setting `config.insecure=true` together with a certificate source is rejected at render time, because the server refuses to start with both.

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
