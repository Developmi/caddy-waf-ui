# Changelog - caddy-waf-ui

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/) · Versioning: [Semantic Versioning](https://semver.org/)

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