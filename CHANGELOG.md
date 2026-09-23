# Changelog - caddy-waf-ui

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/) · Versioning: [Semantic Versioning](https://semver.org/)

---

## [1.1.1] - 2026-09-23

### Security

* **Supply Chain Integrity**: Implemented cryptographic SHA256 checksum verification in `tools/install.sh` and `tools/versions.mk` for pre-compiled third-party tool binaries (`actionlint`, `hadolint`, `golangci-lint`), enforcing fail-closed integrity prior to extraction and execution.
* **Container Hardening**: Defined explicit memory and CPU constraints across all Compose services, added bounded JSON log rotation (`max-size: "10m"`, `max-file: "3"`), and enforced container lockdown directives (`no-new-privileges: true`, `cap_drop: [ALL]`, `tmpfs`) on the `ui-config-init` service.
* **Workflow Permissions**: Enforced least-privilege scoping in `docker-build-scan-sign.yml` by reducing workflow-level permissions to `contents: read` and scoping write capabilities (`packages`, `id-token`, `attestations`, `security-events`) exclusively to the build and publish job.

### Fixed

* **Dockerfile Package Pins**: Updated pinned Alpine 3.23 package versions (`ca-certificates=20260909-r0`, `tzdata=2026d-r0`) to resolve upstream package repository breakage during Docker image builds while retaining the `openssl=3.5.8-r0` pin for CVE-2026-14456 mitigation.

### Changed

* **CI Efficiency**: Added concurrency groups (`cancel-in-progress: true`) and markdown path filters (`paths-ignore`) to build and lint workflows to eliminate redundant runner consumption.
* **Documentation & Metadata**: Synchronized badges, manifest versions, and supported security matrices to `v1.1.1`. Translated residual Spanish comments in `.env.example` and aligned non-root user documentation in `AGENTS.md`.

---

## [1.1.0] - 2026-09-07

### Security

* **CVE-2026-14456 (OpenSSL DoS)**: Pinned `openssl=3.5.8-r0` in the runtime image (transient pin; tracked in the Dockerfile comment for removal once alpine 3.23.6/3.24.2 publish the fixed version). Trivy gate now reports 0 HIGH/CRITICAL findings for the image.
* **Login rate limiting**: Token-bucket limiter (zero-dependency, stdlib only) on `POST /login` — 5 attempts/min per client plus a 60/min global ceiling, `429 + Retry-After` without `Set-Cookie`. Failed logins now emit a structured `slog` security event (`login rejected`, `remote_ip`) without logging credentials.
* **API rate limiting**: `/api/*` limited to 120 req/min with burst 30, applied outside authentication so unauthenticated probes also burn budget. `/health`, `/static/` and SSR page GETs stay exempt.
* **Session cookie expiry**: `Max-Age=43200` (12h) on the session cookie, bounding the exposure window after a manual token rotation (stateless design kept; logout unchanged).
* **Server hardening**: `WriteTimeout: 30s`, `IdleTimeout: 60s`, `MaxHeaderBytes: 1 MiB` alongside the existing `ReadHeaderTimeout` (via extracted `newServer`). Conditional HSTS (`max-age=31536000`) emitted only when `X-Forwarded-Proto: https` is present, so it activates automatically behind a TLS-terminating proxy without breaking loopback/Tailscale HTTP access.
* **CI supply-chain gates**: `govulncheck` pinned to `v1.7.0` in `tools/versions.mk` and run as `make vuln` on PRs and main (no more floating `@latest`; integrity via Go checksum DB). Trivy SARIF now uploads on main and even when the gate fails (`if: always()`), so findings reach the Security tab while the fail-on-HIGH/CRITICAL gate stays enforced.
* **Docs**: `README.md`, `.env.example` and `SECURITY.md` document the LAN exposure risk of the default `CADDY_UI_BIND=0.0.0.0:8080` and the loopback/Tailscale mitigations. The default binding is intentionally unchanged.

### Changed

* **Full ES→EN normalization**: All source comments, log/error messages, user-visible API messages and test case names translated from Spanish to English. Removed the `misspell` Spanish-word exclusion from `.golangci.yml`; `make lint-go` reports 0 issues. No behavior, identifier, route, or env-var changes.

---

## [1.0.0] - 2026-08-21

### Added

* **Core Architecture & Integration**: Initial project scaffold. Added `INTEGRATION.md` defining the three-repo deployment contract, two-channel model (GitOps baseline vs UI runtime deltas), per-slug imports, drift sync, emergency change procedure, and compensating controls.
* **WAF & Security Configurations**:
* WAF mode toggle per site (DetectionOnly / On / Off).
* CRS exclusion CRUD per site (by ID and tag). Parameter-scoped exclusions generate `ARGS:<param>` rules with auto-assigned IDs (9000001+); URI-level exclusions stay as bare `SecRuleRemoveById/Tag`.
* IP allowlist/denylist per site using Caddy native matchers.
* **Web UI (SSR)**: 7 server-rendered pages (login, overview, sites, exclusions, IP rules, logs, rollback) via `html/template` and `go:embed`. Implemented PRG (Post/Redirect/Get) flow with flash messages. Branded as **Caddy WAF UI** with a WCAG AA accessibility pass (responsive scaling, ≥4.5:1 contrast, sequential headings, labeled controls, and keyboard-focusable toast dismiss).
* **Audit & Access Logging**:
* Structured JSON access logging (NIST AU-12): Every authenticated request (and CSRF 403 rejections) emits a `ui_request` entry with method, path, remote IP, and status.
* Coraza audit log reader: Bounded tail read (2 MiB, no streaming) of `CADDY_UI_AUDIT_LOG` (default `/data/logs/coraza-audit.log`) with action filtering, case-insensitive search, and pagination.
* **Snapshots & Rollback**: Snapshot system on write (retaining 10 snapshots per domain). Added `GET /api/sites/{domain}/backups` and `POST /api/sites/{domain}/rollback` REST endpoints, alongside a manual Rollback UI tab.
* **Environment & Infrastructure**:
* `CADDY_UI_LOG_LEVEL` (debug/info/warn/error) controls runtime-tunable JSON log level.
* `CADDY_UI_CADDYFILE` (default `/etc/caddy/Caddyfile`) read by reload and sent to `POST /load`.
* `CADDY_UI_INCLUDE_DIR` defines the Caddy-side view of the overlay directory.
* Docker Compose stack with `ui-managed/` volume isolation. Includes a `ui-config-init` one-shot service to safely create missing overlay imports before Caddy starts. Root `.gitignore` and `.dockerignore` exclude secrets/artifacts. Added public `GET /health` endpoint for container HEALTHCHECK.
* **Service Layer & Reloads**: Consolidated operations into a shared `internal/service` layer that executes the `validate → backup → generate → write → reload → audit` chain. Includes automatic overlay restore if the Caddy hot-reload fails, leaving no partial overlay.
* **File System Writes**: Overlays now use atomic file writes (`write-temp → rename`) and are written as `0644` (world-readable) so the Caddy container (uid 1337) can read them. Overlays contain no secrets.
* **Overlay Structure**: WAF mode overlay is now an inline `coraza_waf { ... }` block (no named snippet wrapper) directly importable inside site blocks.

### Security

* **Domain Validation**: `ValidateDomain` enforces strict RFC 1035 hostnames before any use in paths, templates, or backups. Invalid domains return a `400 Bad Request` (`ErrInvalidDomain`).
* **Hardened UI Container**: Read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, and OCI labels. Pipeline Trivy scans now include `secret` and `misconfig`.
* **Authentication & CSRF**: Cookie-session login (HttpOnly, Secure, SameSite=Strict) and HMAC-CSRF double-submit protection on every form. API uses constant-time Bearer token comparison.