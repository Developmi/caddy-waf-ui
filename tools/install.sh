#!/usr/bin/env bash

# Install the development tools used by the Makefile quality gates.
# Idempotent: skips binaries already present in tools/bin unless REINSTALL=1.
# golangci-lint, hadolint and actionlint are pinned via tools/versions.mk;
# govulncheck is installed with the local Go toolchain (GOBIN=tools/bin).

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/tools/bin"

mkdir -p "$BIN"

: "${ACTIONLINT_VERSION:?}"
: "${HADOLINT_VERSION:?}"
: "${GOLANGCI_VERSION:?}"

INSTALLED=0

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
Linux) OS=linux ;;
Darwin) OS=darwin ;;
*)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
x86_64 | amd64) ARCH=amd64 ;;
arm64 | aarch64) ARCH=arm64 ;;
*)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

download() {
    curl -fsSL "$1" -o "$2"
}

install_actionlint() {
    [[ "${REINSTALL:-}" = "1" ]] && rm -f "$BIN/actionlint"
    [[ -x "$BIN/actionlint" ]] && return

    INSTALLED=1

    echo "Installing actionlint..."

    TMP="$(mktemp -d)"

    curl -fsSL \
        "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_${OS}_${ARCH}.tar.gz" \
        | tar -xz -C "$TMP"

    install "$TMP/actionlint" "$BIN/actionlint"

    rm -rf "$TMP"
}

install_hadolint() {
    [[ "${REINSTALL:-}" = "1" ]] && rm -f "$BIN/hadolint"
    [[ -x "$BIN/hadolint" ]] && return

    INSTALLED=1

    echo "Installing hadolint..."

    case "$OS-$ARCH" in
        linux-amd64)
            FILE="hadolint-linux-x86_64"
            ;;
        linux-arm64)
            FILE="hadolint-linux-arm64"
            ;;
        darwin-amd64)
            FILE="hadolint-Darwin-x86_64"
            ;;
        darwin-arm64)
            FILE="hadolint-Darwin-arm64"
            ;;
    esac

    download \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/${FILE}" \
        "$BIN/hadolint"

    chmod +x "$BIN/hadolint"
}

install_golangci() {
    [[ "${REINSTALL:-}" = "1" ]] && rm -f "$BIN/golangci-lint"
    [[ -x "$BIN/golangci-lint" ]] && return

    INSTALLED=1

    echo "Installing golangci-lint..."

    TMP="$(mktemp -d)"

    curl -fsSL \
        "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_VERSION}/golangci-lint-${GOLANGCI_VERSION}-${OS}-${ARCH}.tar.gz" \
        | tar -xz -C "$TMP"

    install \
        "$TMP/golangci-lint-${GOLANGCI_VERSION}-${OS}-${ARCH}/golangci-lint" \
        "$BIN/golangci-lint"

    rm -rf "$TMP"
}

install_govulncheck() {
    [[ "${REINSTALL:-}" = "1" ]] && rm -f "$BIN/govulncheck"
    [[ -x "$BIN/govulncheck" ]] && return

    INSTALLED=1

    echo "Installing govulncheck (go install)..."

    GOBIN="$BIN" go install golang.org/x/vuln/cmd/govulncheck@latest
}

install_actionlint
install_hadolint
install_golangci
install_govulncheck

if [[ "$INSTALLED" -eq 1 ]]; then
    echo
    echo "✓ Development tools installed."
fi
