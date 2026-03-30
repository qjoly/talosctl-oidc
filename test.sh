#!/usr/bin/env bash
# test.sh - Local end-to-end test environment for talosctl-oidc
#
# Sets up a Dex OIDC provider in Docker (or Podman), generates a self-signed Talos CA,
# and starts the talosctl-oidc server so that you can exercise the full
# authentication flow from a second terminal.
#
# Usage:
#   ./test.sh
#
# Then, in a separate terminal:
#   ./talosctl-oidc login --provider http://localhost:5556/dex \
#       --client-id talosctl-oidc \
#       --server http://localhost:8080 \
#       --insecure

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
DEX_PORT="${DEX_PORT:-5556}"
SERVER_PORT="${SERVER_PORT:-8080}"
CALLBACK_PORT="${CALLBACK_PORT:-8900}"
CLIENT_ID="talosctl-oidc"
DEX_CONTAINER_NAME="talosctl-oidc-dex"
TEST_DIR="$(pwd)/test-env"
BINARY="./talosctl-oidc"

# ── Container runtime detection ──────────────────────────────────────────────
if command -v docker &>/dev/null; then
    CONTAINER_RUNTIME="docker"
elif command -v podman &>/dev/null; then
    CONTAINER_RUNTIME="podman"
else
    CONTAINER_RUNTIME=""
fi

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    log_info "Stopping Dex container..."
    "$CONTAINER_RUNTIME" rm -f "$DEX_CONTAINER_NAME" 2>/dev/null || true
    log_info "Cleanup complete."
}
trap cleanup EXIT

# ── Prerequisites ─────────────────────────────────────────────────────────────
check_prerequisites() {
    log_step "Checking prerequisites..."
    local missing=0

    if [ -z "$CONTAINER_RUNTIME" ]; then
        log_error "'docker' or 'podman' is required but neither was found in PATH."
        missing=1
    fi

    for cmd in openssl curl; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "'$cmd' is required but not found in PATH."
            missing=1
        fi
    done

    if [ "$missing" -ne 0 ]; then
        log_error "Please install the missing tools and re-run."
        exit 1
    fi

    if ! "$CONTAINER_RUNTIME" info &>/dev/null; then
        log_error "$CONTAINER_RUNTIME daemon is not running."
        exit 1
    fi

    log_info "Using container runtime: $CONTAINER_RUNTIME"
    log_info "All prerequisites satisfied."
}

# ── Binary ────────────────────────────────────────────────────────────────────
build_binary() {
    if [ -f "$BINARY" ]; then
        log_info "Using existing binary: $BINARY"
        return
    fi

    log_step "Building talosctl-oidc binary..."
    if ! command -v go &>/dev/null; then
        log_error "'go' is required to build the binary (or put a pre-built 'talosctl-oidc' in the repo root)."
        exit 1
    fi
    go build -o talosctl-oidc .
    log_info "Binary built successfully."
}

# ── Test CA ───────────────────────────────────────────────────────────────────
generate_test_ca() {
    log_step "Generating test CA certificate..."

    if [ -f "$TEST_DIR/ca.crt" ] && [ -f "$TEST_DIR/ca.key" ]; then
        log_info "CA already exists – reusing."
        return
    fi

    openssl genrsa -out "$TEST_DIR/ca.key" 4096 2>/dev/null
    openssl req -new -x509 \
        -key "$TEST_DIR/ca.key" \
        -out "$TEST_DIR/ca.crt" \
        -days 365 \
        -subj "/CN=Test Talos CA/O=Test" \
        2>/dev/null

    log_info "Test CA written to $TEST_DIR/ca.{crt,key}"
}

# ── Dex configuration ─────────────────────────────────────────────────────────
write_dex_config() {
    log_step "Writing Dex configuration..."
    mkdir -p "$TEST_DIR/dex"

    # bcrypt hash of the literal string "password"
    # Generated with: htpasswd -bnBC 10 "" password | tr -d ':\n'
    local password_hash='$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W'

    cat > "$TEST_DIR/dex/config.yaml" << EOF
issuer: http://localhost:${DEX_PORT}/dex

storage:
  type: memory

web:
  http: 0.0.0.0:${DEX_PORT}

logger:
  level: info

oauth2:
  skipApprovalScreen: true
  responseTypes:
    - code

staticClients:
  - id: ${CLIENT_ID}
    name: talosctl-oidc
    public: true
    redirectURIs:
      - http://localhost:${CALLBACK_PORT}/callback
      - http://127.0.0.1:${CALLBACK_PORT}/callback

enablePasswordDB: true
staticPasswords:
  - email: "admin@example.com"
    hash: "${password_hash}"
    username: "admin"
    userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
EOF

    log_info "Dex config written to $TEST_DIR/dex/config.yaml"
    log_info "Static test user: admin@example.com / password"
}

# ── Start Dex ─────────────────────────────────────────────────────────────────
start_dex() {
    log_step "Starting Dex OIDC provider ($CONTAINER_RUNTIME)..."

    "$CONTAINER_RUNTIME" rm -f "$DEX_CONTAINER_NAME" 2>/dev/null || true

    "$CONTAINER_RUNTIME" run -d \
        --name "$DEX_CONTAINER_NAME" \
        -p "${DEX_PORT}:${DEX_PORT}" \
        -v "${TEST_DIR}/dex:/dex-config:ro" \
        dexidp/dex:v2.45.1 \
        dex serve /dex-config/config.yaml

    log_info "Waiting for Dex to become healthy..."
    local waited=0
    local max_wait=60
    until curl -sf "http://localhost:${DEX_PORT}/dex/.well-known/openid-configuration" >/dev/null 2>&1; do
        if [ "$waited" -ge "$max_wait" ]; then
            log_error "Dex did not become healthy within ${max_wait}s."
            "$CONTAINER_RUNTIME" logs "$DEX_CONTAINER_NAME"
            exit 1
        fi
        sleep 1
        waited=$((waited + 1))
    done

    log_info "Dex is ready at http://localhost:${DEX_PORT}/dex"
}

# ── Server configuration ──────────────────────────────────────────────────────
write_server_config() {
    log_step "Writing talosctl-oidc server configuration..."
    mkdir -p "$TEST_DIR/server-data"

    cat > "$TEST_DIR/server-config.yaml" << EOF
# OIDC provider (Dex running locally via $CONTAINER_RUNTIME)
issuer_url: http://localhost:${DEX_PORT}/dex
client_id: ${CLIENT_ID}

# Test Talos CA (self-signed, for local testing only)
ca_cert: ${TEST_DIR}/ca.crt
ca_key: ${TEST_DIR}/ca.key

# Server
listen: ":${SERVER_PORT}"

# Placeholder endpoint (no real Talos cluster needed to test the auth flow)
endpoints:
  - localhost

# Short TTL for testing
cert_ttl: "5m"

# Roles assigned to every authenticated user
roles:
  - os:admin

# Serve plain HTTP for local testing (no TLS setup required)
insecure: true

# Persist generated self-signed TLS cert across restarts (not used in insecure mode)
data_dir: ${TEST_DIR}/server-data

# Audit log
audit_log: ${TEST_DIR}/audit.log
EOF

    log_info "Server config written to $TEST_DIR/server-config.yaml"
}

# ── Usage banner ──────────────────────────────────────────────────────────────
print_banner() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          talosctl-oidc local test environment            ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BLUE}Dex (OIDC provider):${NC}  http://localhost:${DEX_PORT}/dex"
    echo -e "  ${BLUE}cert-exchange server:${NC}  http://localhost:${SERVER_PORT}"
    echo ""
    echo -e "  ${YELLOW}Test credentials:${NC}"
    echo "    Email:    admin@example.com"
    echo "    Password: password"
    echo ""
    echo -e "  ${YELLOW}Run the login client in a separate terminal:${NC}"
    echo ""
    echo "    ./talosctl-oidc login \\"
    echo "      --provider http://localhost:${DEX_PORT}/dex \\"
    echo "      --client-id ${CLIENT_ID} \\"
    echo "      --server http://localhost:${SERVER_PORT} \\"
    echo "      --insecure \\"
    echo "      --callback-port ${CALLBACK_PORT}"
    echo ""
    echo -e "  ${YELLOW}Press Ctrl+C to stop the server and clean up.${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_prerequisites
    mkdir -p "$TEST_DIR"
    generate_test_ca
    write_dex_config
    start_dex
    write_server_config
    build_binary
    print_banner

    log_step "Starting talosctl-oidc server (Ctrl+C to stop)..."
    "$BINARY" serve --config "$TEST_DIR/server-config.yaml"
}

main
