# talosctl-oidc

OIDC-gated credential plugin for [talosctl](https://www.talos.dev/). Authenticates users through any standard OIDC provider before writing pre-provisioned Talos client certificates into the `talosconfig`.

## How It Works

Talos Linux uses **mTLS (mutual TLS) with client certificates** for API authentication. There is no native OIDC support in the Talos API. This tool bridges the gap by acting as a gatekeeper:

1. The user runs `talosctl-oidc login`
2. A browser window opens for OIDC authentication (Authorization Code flow with PKCE)
3. Upon successful login, the tool writes pre-provisioned admin client certificates into `~/.talos/config`
4. The user can then use `talosctl` normally

OIDC tokens are cached in the **system keychain** (macOS Keychain, GNOME Keyring, KDE Wallet, or Windows Credential Manager). On subsequent runs, if the token is still valid the browser step is skipped. Expired tokens are refreshed automatically when a refresh token is available.

```
                         +------------------+
                         |  OIDC Provider   |
                         | (Keycloak, Dex,  |
                         |  Authelia, etc.) |
                         +--------+---------+
                                  |
                    Authorization Code + PKCE
                                  |
+----------+    login    +--------v---------+    writes certs    +----------------+
|  Browser |<------------|  talosctl-oidc   |------------------>|  ~/.talos/config|
+----------+             +------------------+                   +-------+--------+
                                  |                                     |
                           stores token                          talosctl reads
                                  |                                     |
                         +--------v---------+                   +-------v--------+
                         | System Keychain  |                   |   Talos Node   |
                         +------------------+                   +----------------+
```

## Prerequisites

- **Go 1.21+** (to build from source)
- **A running Talos cluster** with API access
- **Pre-provisioned client certificates** (CA cert, client cert, client key) with admin privileges on the Talos nodes
- **An OIDC provider** with a configured client application (any OIDC-compliant provider works)

## Installation

### From source

```bash
git clone https://github.com/qjoly/talosctl-oidc.git
cd talosctl-oidc
go build -o talosctl-oidc .
```

Move the binary to a directory in your `$PATH`:

```bash
sudo mv talosctl-oidc /usr/local/bin/
```

## Setup

### 1. Configure your OIDC provider

Create a client application in your OIDC provider with the following settings:

| Setting | Value |
|---------|-------|
| Client type | Public (recommended) or Confidential |
| Grant type | Authorization Code |
| Redirect URI | `http://127.0.0.1:8900/callback` |
| Scopes | `openid`, `profile`, `email` |
| PKCE | Enabled (S256) |

#### Keycloak example

1. Go to your Keycloak admin console
2. Select your realm (or create one, e.g. `talos`)
3. Go to **Clients** > **Create client**
4. Set **Client ID** to `talosctl` (or any name you prefer)
5. Set **Client authentication** to **Off** (public client)
6. Enable **Standard flow** (Authorization Code)
7. Set **Valid redirect URIs** to `http://127.0.0.1:8900/callback`
8. Under **Advanced** > **Proof Key for Code Exchange**, set to `S256`
9. Save

#### Dex example

Add this to your Dex configuration:

```yaml
staticClients:
  - id: talosctl
    name: "Talosctl OIDC"
    redirectURIs:
      - "http://127.0.0.1:8900/callback"
    public: true
```

#### Authelia example

Add this to your Authelia configuration:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: talosctl
        client_name: "Talosctl OIDC"
        public: true
        authorization_policy: two_factor
        redirect_uris:
          - http://127.0.0.1:8900/callback
        scopes:
          - openid
          - profile
          - email
        pkce_challenge_method: S256
```

### 2. Obtain Talos client certificates

You need pre-provisioned admin client certificates for your Talos cluster. These are typically generated during cluster bootstrapping. You can extract them from an existing `talosconfig`:

```bash
# Extract from an existing talosconfig
talosctl config info

# Or generate new client certificates
talosctl gen config my-cluster https://<controlplane-ip>:6443
# This creates talosconfig with embedded certs
```

Extract the individual certificate files from your existing `talosconfig`:

```bash
# Decode the base64 certificates from an existing talosconfig
talosctl config info --output json | jq -r '.ca' | base64 -d > talos-ca.crt
talosctl config info --output json | jq -r '.crt' | base64 -d > talos-admin.crt
talosctl config info --output json | jq -r '.key' | base64 -d > talos-admin.key
```

Or if you have the raw certificate files from your cluster bootstrap, use those directly.

Store these files in a secure location (e.g. `~/.talos/certs/`):

```bash
mkdir -p ~/.talos/certs
chmod 700 ~/.talos/certs
mv talos-ca.crt talos-admin.crt talos-admin.key ~/.talos/certs/
chmod 600 ~/.talos/certs/*
```

### 3. Login

```bash
talosctl-oidc login \
  --provider https://idp.example.com/realms/talos \
  --client-id talosctl \
  --ca-cert ~/.talos/certs/talos-ca.crt \
  --client-cert ~/.talos/certs/talos-admin.crt \
  --client-key ~/.talos/certs/talos-admin.key \
  --endpoints 10.0.0.1,10.0.0.2,10.0.0.3
```

This will:
1. Open your browser to the OIDC provider login page
2. Wait for you to authenticate
3. Cache the OIDC token in your system keychain
4. Write the certificates to `~/.talos/config` under the `oidc` context
5. Set `oidc` as the active context

### 4. Use talosctl

After login, `talosctl` works normally using the `oidc` context:

```bash
talosctl version
talosctl get members
talosctl dashboard
```

Or explicitly select the context:

```bash
talosctl --context oidc version
```

## Commands

### `login`

Authenticate via OIDC and write credentials to talosconfig.

```bash
talosctl-oidc login [flags]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--provider` | Yes | | OIDC issuer URL |
| `--client-id` | Yes | | OIDC client ID |
| `--ca-cert` | Yes | | Path to Talos CA certificate |
| `--client-cert` | Yes | | Path to pre-provisioned client certificate |
| `--client-key` | Yes | | Path to pre-provisioned client key |
| `--endpoints` | Yes | | Talos node endpoints (comma-separated) |
| `--client-secret` | No | | OIDC client secret (for confidential clients) |
| `--scopes` | No | `openid,profile,email` | OIDC scopes |
| `--callback-port` | No | `8900` | Local callback server port |
| `--context-name` | No | `oidc` | Name for the talosconfig context |
| `--talosconfig` | No | `~/.talos/config` | Path to talosconfig file |

### `logout`

Remove OIDC credentials and clear cached tokens.

```bash
talosctl-oidc logout [flags]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--context-name` | No | `oidc` | Name of the talosconfig context to remove |
| `--talosconfig` | No | `~/.talos/config` | Path to talosconfig file |

This removes:
- The OIDC token from the system keychain
- The context (including embedded certificates) from the talosconfig file

### `status`

Display current authentication status.

```bash
talosctl-oidc status [flags]
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--context-name` | No | `oidc` | Name of the talosconfig context to check |
| `--talosconfig` | No | `~/.talos/config` | Path to talosconfig file |

Example output:

```
Context: oidc

--- OIDC Token ---
Issuer:    https://idp.example.com/realms/talos
Client ID: talosctl
Status:    valid (expires in 4m30s)
Refresh:   available

--- Talosconfig ---
Path:      /home/user/.talos/config
Status:    context "oidc" exists
Endpoints: [10.0.0.1 10.0.0.2 10.0.0.3]
Active:    yes (current context)
Client cert: present
```

## Token Caching Behavior

The `login` command handles tokens intelligently:

| Scenario | Behavior |
|----------|----------|
| No cached token | Opens browser for full OIDC login |
| Valid cached token | Skips browser, writes certs immediately |
| Expired token with refresh token | Silently refreshes, no browser needed |
| Expired token without refresh token | Opens browser for full OIDC login |
| Refresh fails | Falls back to full OIDC login |

The login flow has a **5-minute timeout**. If the user does not complete authentication in the browser within that window, the command exits with an error.

## Multiple Clusters

Use `--context-name` to manage credentials for different Talos clusters:

```bash
# Login to production cluster
talosctl-oidc login \
  --provider https://idp.example.com/realms/talos \
  --client-id talosctl \
  --context-name prod \
  --ca-cert ~/.talos/certs/prod-ca.crt \
  --client-cert ~/.talos/certs/prod-admin.crt \
  --client-key ~/.talos/certs/prod-admin.key \
  --endpoints 10.0.0.1

# Login to staging cluster
talosctl-oidc login \
  --provider https://idp.example.com/realms/talos \
  --client-id talosctl \
  --context-name staging \
  --ca-cert ~/.talos/certs/staging-ca.crt \
  --client-cert ~/.talos/certs/staging-admin.crt \
  --client-key ~/.talos/certs/staging-admin.key \
  --endpoints 10.1.0.1

# Switch between clusters
talosctl --context prod version
talosctl --context staging version

# Check status of each
talosctl-oidc status --context-name prod
talosctl-oidc status --context-name staging
```

## Security Considerations

- **PKCE is mandatory** for the OIDC flow (S256 challenge method), protecting against authorization code interception attacks
- **OIDC tokens are stored in the system keychain**, encrypted at rest by the operating system
- **Client certificates are embedded in `~/.talos/config`** with `0600` permissions (same as standard talosctl behavior)
- **The callback server binds to `127.0.0.1` only**, preventing access from other machines on the network
- **State parameter** is used for CSRF protection during the OIDC flow
- Running `logout` removes both the keychain token and the certificates from the talosconfig

## Troubleshooting

### "failed to listen on port 8900"

Another process is using port 8900. Use `--callback-port` to pick a different port. Make sure the redirect URI in your OIDC provider matches (e.g. `http://127.0.0.1:9000/callback`).

### "OIDC discovery failed"

The tool could not reach the OIDC provider's `/.well-known/openid-configuration` endpoint. Verify:
- The `--provider` URL is correct and reachable
- The URL does not have a trailing slash issue
- Your network/proxy allows access to the provider

### "state mismatch: possible CSRF attack"

The state parameter returned by the OIDC provider does not match what was sent. This could indicate a CSRF attack or a stale browser tab. Try the login again.

### Keychain errors on Linux

On Linux, `go-keyring` requires a running secret service (GNOME Keyring or KDE Wallet). If you are on a headless server, you may need to install and configure `gnome-keyring` or use `--context-name` with a specific name to help identify entries.

```bash
# Install GNOME Keyring on Debian/Ubuntu
sudo apt install gnome-keyring

# On headless systems, you may need to unlock the keyring first
eval $(gnome-keyring-daemon --start --components=secrets)
export GNOME_KEYRING_CONTROL
```
