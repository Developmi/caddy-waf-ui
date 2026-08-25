# Contributing to caddy-waf-ui

Thank you for your interest in contributing. This project follows the Developmi engineering standard.

## Development setup

Requirements:

- Go 1.26.x - `go.mod` pins `go 1.26.4` with `toolchain go1.26.6` (newer Go auto-downloads the pinned toolchain)
- Docker (and Docker Compose v2) - for the full stack and image builds
- [uv](https://docs.astral.sh/uv/) - for Python tooling (yamllint, zizmor)

```bash
# Clone the repository
git clone https://github.com/Developmi/caddy-waf-ui.git
cd caddy-waf-ui

# Copy the environment template
cp .env.example .env

# Copy the Caddyfile template
cp Caddyfile.example Caddyfile

# Install the pinned development tools (golangci-lint, hadolint, actionlint, govulncheck)
make tools
```

> `Caddyfile` is gitignored by design (see `.gitignore`): it is per-environment
> configuration (site address, ACME email, backend upstream) and must not be
> committed. Only `Caddyfile.example` is tracked - CI is clone-safe and never
> requires a local `Caddyfile`.

## Commit standard

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(ui): add per-site rate limit toggle
fix(auth): resolve token refresh race condition
docs: update README with deployment instructions
chore(config): bump Go toolchain to 1.26.6
refactor(api): extract WAF mode service
perf(handlers): reduce allocations in audit log view
test(integration): cover rollback snapshot ordering
ci(workflows): add SBOM generation to release pipeline
```

Types: `feat` · `fix` · `docs` · `chore` · `refactor` · `perf` · `test` · `ci`

## Branch naming

```
feat/short-description
fix/issue-number-description
docs/update-readme
chore/bump-dependencies
ci/update-workflow
```

## Pull request process

1. Fork the repository and create your branch from `main`.
2. Make your changes, following the existing code style and architecture (see ARCHITECTURE.md).
3. Run the local quality gates: `make lint`, `make test-race`, `make vuln`, `make build`. Before pushing or opening a PR, you **must** run the full pre-push gate: `make release-ready` (see [Testing](#testing)). If it fails, do not push - fix the findings and re-run until it passes.
4. Ensure any new environment variables are documented in `.env.example`.
5. Update documentation if your change affects public behavior (README, SECURITY, INTEGRATION).
6. Add a CHANGELOG entry if the change is user-visible.
7. Open a PR with a clear title following the commit standard. CI runs lint, unit tests (race detector), build, and compose validation on every PR. For releases, CI runs on tag push (`v*`) - the full pipeline builds, scans, signs, and pushes the multi-arch image to GHCR.
8. A maintainer will review within 5 business days.

## Reporting issues

Use [GitHub Issues](https://github.com/Developmi/caddy-waf-ui/issues). Include:
- Steps to reproduce
- Expected vs. actual behavior
- UI version and WAF version, Docker version, and platform (linux/amd64, linux/arm64)
- Relevant log output (`docker compose logs caddy-waf-ui`, Caddy admin log)

For security vulnerabilities, do not open a public issue - see [SECURITY.md](./SECURITY.md).

## Code of conduct

This project adheres to the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Testing

Before submitting a PR, run the full quality suite:

```bash
make lint          # golangci-lint, yamllint, actionlint, hadolint, zizmor
make test-race     # unit tests with the race detector
make vuln          # govulncheck against known vulnerabilities
make build         # compile all packages
```

### Pre-push gate

Before pushing your branch or opening a PR, run the complete gate:

```bash
make release-ready   # fmt, vet, lint, vuln, test-race, compose-config, build, docker-build
```

`make release-ready` chains every quality target in order - `fmt`, `vet`, `lint`, `vuln`, `test-race`, `compose-config`, `build`, `docker-build`. Any failure aborts the gate: **if it fails, do not push**. Fix the findings and re-run until the gate passes.

Requires `make tools` to install the pinned linters.
