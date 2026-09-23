# Pinned tool versions shared by the Makefile and tools/install.sh.
# Keep in sync with the sibling repo (caddy-waf): do not float to latest.
ACTIONLINT_VERSION := 1.7.12
HADOLINT_VERSION   := 2.15.1
GOLANGCI_VERSION   := 2.12.2

# SHA256 of official release assets, named <TOOL>_SHA256_<OS>_<ARCH>.
# sources (fetched 2026-09-09 from official release checksums assets):
#   actionlint    v1.7.12    actionlint_1.7.12_checksums.txt
#   hadolint      v2.15.1    checksums.sha256
#   golangci-lint v2.12.2    golangci-lint-2.12.2-checksums.txt
ACTIONLINT_SHA256_LINUX_AMD64  := 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ACTIONLINT_SHA256_LINUX_ARM64  := 325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
ACTIONLINT_SHA256_DARWIN_AMD64 := 5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644
ACTIONLINT_SHA256_DARWIN_ARM64 := aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
HADOLINT_SHA256_LINUX_AMD64   := c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
HADOLINT_SHA256_LINUX_ARM64   := f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d
HADOLINT_SHA256_DARWIN_AMD64  := ffe9bb18b23d5ed1eae50237aecdbb523d016e96da0bd4e7aa432040acfc3fde
HADOLINT_SHA256_DARWIN_ARM64  := 5c09f3213f8e40406abe048233d985eebef336d4a6a20021be47fadb6cf480a2
GOLANGCI_SHA256_LINUX_AMD64  := 8df580d2670fed8fa984aac0507099af8df275e665215f5c7a2ae3943893a553
GOLANGCI_SHA256_LINUX_ARM64  := 44cd40a8c76c86755375adfeea52cfd3533cb43d7bd647771e0ae065e166df3a
GOLANGCI_SHA256_DARWIN_AMD64 := f6f06d94b6241521c53d15450c5209b028270bf966f842afb11c030c79f5bc16
GOLANGCI_SHA256_DARWIN_ARM64 := a9c54498731b3128f79e090be6110f3e5fffccc617b08142ed244d4126c73f29

# govulncheck (CI-1/CI-2, D9 adapted): golang.org/x/vuln publishes NO release
# binaries (verified 2026-09-06: assets=0 on v1.0.0..v1.1.4 releases; tags
# v1.2.0-v1.7.0 have no GitHub Release), so there are no per-OS/ARCH release
# archives or GOVULNCHECK_SHA256_{OS}_{ARCH} digests to pin. The version is
# installed with `go install golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK_VERSION}`
# and integrity is enforced by the Go checksum DB (GOSUMDB=sum.golang.org).
# TODO: if upstream ever publishes release assets + checksums, add the SHA256
# digests per platform and verify the archive before installing (install.sh).
GOVULNCHECK_VERSION := 1.7.0
