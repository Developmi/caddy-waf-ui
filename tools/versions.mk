# Pinned tool versions shared by the Makefile and tools/install.sh.
# Keep in sync with the sibling repo (caddy-waf): do not float to latest.
ACTIONLINT_VERSION := 1.7.12
HADOLINT_VERSION   := 2.15.1
GOLANGCI_VERSION   := 2.12.2
# govulncheck (CI-1/CI-2, D9 adapted): golang.org/x/vuln publishes NO release
# binaries (verified 2026-09-06: assets=0 on v1.0.0..v1.1.4 releases; tags
# v1.2.0-v1.7.0 have no GitHub Release), so there are no per-OS/ARCH release
# archives or GOVULNCHECK_SHA256_{OS}_{ARCH} digests to pin. The version is
# installed with `go install golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK_VERSION}`
# and integrity is enforced by the Go checksum DB (GOSUMDB=sum.golang.org).
# TODO: if upstream ever publishes release assets + checksums, add the SHA256
# digests per platform and verify the archive before installing (install.sh).
GOVULNCHECK_VERSION := 1.7.0
