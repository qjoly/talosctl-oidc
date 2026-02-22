#!/bin/sh
# install.sh — Install talosctl-oidc
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/qjoly/talosctl-oidc/main/install.sh | sh
#
# Options (environment variables):
#   VERSION      — specific release tag to install (default: latest)
#   INSTALL_DIR  — directory to install the binary (default: /usr/local/bin,
#                  falls back to ~/.local/bin when /usr/local/bin is not writable)
#   BINARY_NAME  — name for the installed binary (default: talosctl-oidc)
#
# Example: install a specific version
#   curl -fsSL .../install.sh | VERSION=v0.3.1 sh

set -eu

REPO="qjoly/talosctl-oidc"
BINARY_NAME="${BINARY_NAME:-talosctl-oidc}"
INSTALL_DIR="${INSTALL_DIR:-}"   # resolved below

# ── helpers ──────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m  info\033[0m  %s\n' "$*"; }
ok()    { printf '\033[1;32m    ok\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m  warn\033[0m  %s\n' "$*"; }
fatal() { printf '\033[1;31m error\033[0m  %s\n' "$*" >&2; exit 1; }

need() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || fatal "Required command not found: $cmd"
    done
}

# ── dependency check ─────────────────────────────────────────────────────────

need curl uname

# ── detect OS ────────────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux*)   printf 'linux'   ;;
        Darwin*)  printf 'darwin'  ;;
        MINGW*|MSYS*|CYGWIN*) printf 'windows' ;;
        *) fatal "Unsupported operating system: $(uname -s)" ;;
    esac
}

# ── detect architecture ───────────────────────────────────────────────────────

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   printf 'amd64' ;;
        aarch64|arm64)  printf 'arm64' ;;
        *) fatal "Unsupported architecture: $(uname -m)" ;;
    esac
}

# ── resolve install directory ─────────────────────────────────────────────────

resolve_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        printf '%s' "$INSTALL_DIR"
        return
    fi

    if [ -w /usr/local/bin ]; then
        printf '/usr/local/bin'
    else
        # Fall back to ~/.local/bin (created if needed)
        local_bin="${HOME}/.local/bin"
        mkdir -p "$local_bin"
        printf '%s' "$local_bin"
    fi
}

# ── fetch latest release tag ─────────────────────────────────────────────────

fetch_latest_version() {
    url="https://api.github.com/repos/${REPO}/releases/latest"
    version="$(curl -fsSL "$url" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [ -n "$version" ] || fatal "Could not determine the latest release version."
    printf '%s' "$version"
}

# ── verify checksum ───────────────────────────────────────────────────────────

verify_checksum() {
    file="$1"
    checksums_file="$2"
    basename="$(basename "$file")"

    # Extract the expected hash for this file
    expected="$(grep " ${basename}$" "$checksums_file" | awk '{print $1}')"

    if [ -z "$expected" ]; then
        warn "No checksum entry found for ${basename} — skipping verification."
        return 0
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        warn "Neither sha256sum nor shasum found — skipping checksum verification."
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        fatal "Checksum mismatch for ${basename}!\n  expected: ${expected}\n  actual:   ${actual}"
    fi

    ok "Checksum verified."
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
    OS="$(detect_os)"
    ARCH="$(detect_arch)"

    VERSION="${VERSION:-}"
    if [ -z "$VERSION" ]; then
        info "Fetching latest release version..."
        VERSION="$(fetch_latest_version)"
    fi

    INSTALL_DIR="$(resolve_install_dir)"

    EXT=""
    [ "$OS" = "windows" ] && EXT=".exe"

    ASSET="talosctl-oidc-${OS}-${ARCH}${EXT}"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    ASSET_URL="${BASE_URL}/${ASSET}"
    CHECKSUMS_URL="${BASE_URL}/checksums.txt"

    info "Version  : ${VERSION}"
    info "Platform : ${OS}/${ARCH}"
    info "Asset    : ${ASSET}"
    info "Install  : ${INSTALL_DIR}/${BINARY_NAME}${EXT}"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    # Download binary
    info "Downloading ${ASSET}..."
    curl -fsSL --progress-bar "$ASSET_URL" -o "${TMPDIR}/${ASSET}" || \
        fatal "Download failed: ${ASSET_URL}"

    # Download and verify checksum
    info "Verifying checksum..."
    if curl -fsSL "$CHECKSUMS_URL" -o "${TMPDIR}/checksums.txt" 2>/dev/null; then
        verify_checksum "${TMPDIR}/${ASSET}" "${TMPDIR}/checksums.txt"
    else
        warn "checksums.txt not available for this release — skipping verification."
    fi

    # Install
    chmod +x "${TMPDIR}/${ASSET}"

    DEST="${INSTALL_DIR}/${BINARY_NAME}${EXT}"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMPDIR}/${ASSET}" "$DEST"
    else
        info "Requesting elevated privileges to write to ${INSTALL_DIR}..."
        sudo mv "${TMPDIR}/${ASSET}" "$DEST"
    fi

    ok "Installed to ${DEST}"

    # PATH reminder when ~/.local/bin is used
    case "$INSTALL_DIR" in
        "$HOME"/.local/bin)
            warn "${INSTALL_DIR} is not in your PATH."
            warn "Add this to your shell profile:"
            warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
            ;;
    esac

    # Smoke-test
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        ok "$(${BINARY_NAME} version 2>/dev/null || true)"
    else
        "${DEST}" version 2>/dev/null && true
    fi
}

main
