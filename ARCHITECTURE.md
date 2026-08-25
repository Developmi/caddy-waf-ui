# Architecture - caddy-waf-ui

> This document describes the system design, data flow, component boundaries, and architectural decisions for `caddy-waf-ui`. It is the authoritative reference for contributors and operators.

---

## Table of Contents

- [System Overview](#system-overview)
- [Component Map](#component-map)
- [Data Flow](#data-flow)
- [Volume Architecture](#volume-architecture)
- [Config Ownership Model](#config-ownership-model)
- [UI Request Lifecycle](#ui-request-lifecycle)
- [File Naming Convention](#file-naming-convention)
- [Security Boundaries](#security-boundaries)
- [Architectural Decision Records](#architectural-decision-records)

---

## System Overview

`caddy-waf-ui` is a **sidecar container** - it has no user-facing ingress and no direct relation to the traffic path. It communicates with Caddy exclusively through:

1. A **shared Docker volume** (`caddy-ui-config`) where it writes config overlay files
2. The **Caddy Admin API** (`caddy:2019`, Docker-internal only) to trigger hot-reload

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker Compose Stack                                           │
│                                                                 │
│  ┌──────────────────────────────────┐                          │
│  │  caddy (caddy-waf image)         │                          │
│  │                                  │                          │
│  │  /etc/caddy/Caddyfile  ←  :ro   │◄── Ansible (Caddyfile.j2)│
│  │  /etc/caddy/certs      ←  :ro   │◄── Ansible (cert deploy) │
│  │  /etc/caddy/ui-managed ←  :ro   │◄── caddy-waf-ui writes   │
│  │  /data/logs            ←  :rw   │                          │
│  │                                  │                          │
│  │  :80, :443, :443/udp (public)   │                          │
│  │  :2019 (admin, Docker-internal) │                          │
│  │  (healthcheck: pgrep caddy)     │                          │
│  └──────────┬───────────────────────┘                          │
│             │ Docker network: public_net                        │
│  ┌──────────▼───────────────────────┐                          │
│  │  caddy-waf-ui (this project)     │                          │
│  │                                  │                          │
│  │  /ui-managed  ←  :rw  ──────────┼──► /etc/caddy/ui-managed │
│  │  /backups     ←  :rw            │    (same Docker volume)   │
│  │  reads /data/logs  ←  :ro       │                          │
│  │                                  │                          │
│  │  :8080 (UI, 0.0.0.0 default)    │                          │
│  └──────────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Map

> **MVP status:** the Coraza audit log reader/parser (`logs/reader.go`) and the UI templates
> for logs and rollback are implemented in the MVP. The settings page (CF token management)
> and SSE log streaming remain planned.

```
caddy-waf-ui/
├── cmd/
│   └── server/
│       └── main.go              # Entrypoint - wire dependencies, start HTTP server
├── internal/
│   ├── auth/
│   │   └── bearer.go            # Bearer token middleware (NIST AC-3)
│   ├── caddy/
│   │   └── admin.go             # Caddy Admin API client (POST /load + read-back GET /config/apps/http/servers)
│   ├── config/
│   │   └── config.go            # Centralized env config (single place for names + defaults)
│   ├── domain/
│   │   ├── model.go             # Domain struct - name, mode, exclusions, ip rules
│   │   ├── overlay.go           # Shared overlay header contract (# domain: | mode: | updated:)
│   │   ├── scanner.go           # Discovers domains from ui-managed/ (scan per request)
│   │   └── slug.go              # DomainSlug - filesystem-safe slug for file names
│   ├── service/
│   │   ├── chain.go             # Shared change chain: validate → backup → generate → write → reload → audit (runChain)
│   │   └── validate.go          # ValidateDomain (RFC 1035) → ErrInvalidDomain → 400
│   ├── files/
│   │   ├── writer.go            # Atomic file writes (write temp → rename)
│   │   ├── backup.go            # Snapshot management, retention, diff
│   │   └── naming.go            # File naming convention helpers
│   ├── waf/
│   │   ├── mode.go              # WAF mode toggle logic + Caddyfile snippet generator
│   │   └── exclusions.go        # CRS exclusion CRUD + conf file generator
│   ├── iprules/
│   │   └── rules.go             # IP allowlist/denylist CRUD + Caddy matcher generator
│   ├── logs/
│   │   ├── audit.go             # Coraza audit entry model (reader + SSR UI)
│   │   ├── logger.go            # slog logger setup (level, output)
│   │   └── reader.go            # Bounded tail read of the audit log + JSON parse/filter
│   └── ui/
│       ├── api.go               # REST API handlers (backups, rollback, site state)
│       ├── embed.go             # go:embed template filesystem
│       ├── forms.go             # HTML form handlers (PRG + flash messages)
│       ├── overlay.go           # Overlay PARSER - regexes over generated rule bodies (exclusions/IP-rules round-trip)
│       ├── pages.go             # Server-rendered page handlers
│       ├── router.go            # Route definitions
│       └── templates/           # Go html/template files
│           ├── base.html
│           ├── exclusions.html
│           ├── iprules.html
│           ├── login.html
│           ├── logs.html        # Log viewer - bounded tail read, filters, pagination
│           ├── overview.html
│           ├── rollback.html    # Snapshot history + diff view
│           └── sites.html       # Per-site management (mode + exclusions + IP rules)
├── Dockerfile
├── docker-compose.yml           # Standalone compose (for reference / local dev)
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE
```

---

## Data Flow

### 1. Operator changes WAF mode for a domain

```
Operator (browser)
  │
  │  POST /sites/{domain}/mode  { mode: "On" }
  │  Authorization: Bearer <token>
  ▼
auth middleware → validate token
  ▼
handler: waf.SetMode(domain, "On")
  ▼
files.backup(domain)              # snapshot current waf-{domain}.conf to /backups/
  ▼
waf.generateSnippet(domain, "On") # render Caddyfile snippet with SecRuleEngine On
  ▼
files.atomicWrite(                # write to temp file, then os.Rename (atomic)
  "/ui-managed/waf-{domain}.conf"
)
  ▼
caddy.admin.Reload()              # POST /load with the Caddyfile (text/caddyfile)
  ▼
audit.log(actor, action, domain)  # JSON audit entry to stdout
  ▼
200 OK → full-page SSR re-render (no HTMX; stdlib html/template)
```

### 2. Operator adds a CRS exclusion from the per-domain exclusions page

```
Operator opens the exclusions page for api.example.com (catalog of common
OWASP CRS rules + custom directive form; the page is rendered from the
active overlay via ui/overlay.go parsers)
  │
  │  POST /sites/{domain}/exclusions  { exclusions: [ { type: "id", value: "941100" } ] }
  ▼
handler: service.UpdateExclusions(domain, exclusions, remoteIP)
  ▼
service.ValidateDomain(domain)      # strict RFC 1035 hostname → ErrInvalidDomain → 400
  ▼
waf.ValidateExclusions(exclusions)  # strict regexes (id/tag/param) - fails before backup
  ▼
service.runChain:                   # shared chain - validate → backup → generate → write → reload → audit
  ├─ files.backup(domain)           # snapshot current exclusions-{domain}.conf to /backups/
  ├─ waf.GenerateExclusions(...)    # regenerate the full exclusions conf (with header)
  ├─ files.AtomicWrite("/ui-managed/exclusions-{domain}.conf")   # temp + os.Rename
  ├─ caddy.admin.Reload()           # POST /load with the Caddyfile (text/caddyfile)
  ├─ audit.log(actor, action, domain)  # JSON audit entry to stdout
  └─ on reload failure: restore previous overlay (or remove if it did not exist)
  ▼
200 OK → full-page SSR re-render showing the updated exclusion list (no HTMX)
```

One-click exclusion from a log entry is **planned - not implemented in MVP**; the exclusions page (per-domain form + catalog) is the implemented path.

### 3. Log streaming (planned - not implemented in MVP)

```
logs.Reader tails /data/logs/coraza-audit.log (read-only)
  │
  │  inotify / polling (configurable)
  ▼
logs.Parser → []LogEntry{domain, ruleID, severity, action, uri, remoteIP, ts}
  ▼
logs.Filter → apply active filters from query params
  ▼
HTTP SSE stream → browser renders new entries (SSE planned; no HTMX in codebase)
```

---

## Volume Architecture

Three volumes are involved. Their ownership and permissions are strict by design:

| Volume | Owner | Mount in caddy | Mount in caddy-waf-ui | Purpose |
|---|---|---|---|---|
| `caddy-ui-config` | caddy-waf-ui | `:ro` at `/etc/caddy/ui-managed/` | `:rw` at `/ui-managed/` | UI-generated config overlay |
| `caddy-ui-backups` | caddy-waf-ui | not mounted | `:rw` at `/backups/` | Snapshots, no Caddy access |
| `caddy-data` (existing) | caddy | `:rw` at `/data/` | `:ro` at `/data/logs/` (logs subdir only) | Caddy data + WAF audit logs |

The UI **never** has access to:
- `/etc/caddy/Caddyfile` (Ansible-owned)
- `/etc/caddy/certs/` (cert files)
- `/etc/caddy/owasp-crs/` (CRS rule files)
- `/etc/caddy/coraza.conf` (base Coraza config)

---

## Config Ownership Model

```
/etc/caddy/
├── Caddyfile              ← Ansible owns, caddy-waf-ui has NO access
├── coraza.conf            ← Ansible owns, caddy-waf-ui has NO access
├── certs/                 ← Ansible owns, caddy-waf-ui has NO access
├── owasp-crs/             ← Image ships this, caddy-waf-ui has NO access
└── ui-managed/            ← caddy-waf-ui owns entirely
    ├── waf-api_example_com.conf
    ├── exclusions-api_example_com.conf
    ├── ip-rules-api_example_com.conf
    ├── waf-app_example_com.conf
    ├── exclusions-app_example_com.conf
    └── ip-rules-app_example_com.conf
```

The `Caddyfile` (Ansible template) contains, at the end of each **UI-managed** site block:

```caddyfile
{{ svc.domain }} {
    import /etc/caddy/ui-managed/ip-rules-{{ domain_slug }}.conf
    import /etc/caddy/ui-managed/waf-{{ domain_slug }}.conf
    ...
}
```

`ip-rules-{slug}.conf` is imported first (IP rules run before the WAF - blocked traffic never reaches Coraza), then `waf-{slug}.conf`. Managed blocks never `import waf`: the overlay embeds its own inline `coraza_waf { ... }` block, and a second engine would break the reload. Exclusions enter only through the Coraza internal `Include /etc/caddy/ui-managed/exclusions-{slug}.conf` inside that block - never via the Caddyfile. Unmanaged domains keep `import waf` (base snippet, `SecRuleEngine DetectionOnly`).

A specific import whose file does not exist **hard-fails Caddy startup** - Caddy never skips a specific import (only non-matching globs warn). The Ansible role therefore pre-creates empty placeholders for `ip-rules-{slug}.conf` and `waf-{slug}.conf` before first boot; `exclusions-{slug}.conf` needs none, since the Coraza internal `Include` tolerates absence. See [INTEGRATION.md](./INTEGRATION.md) §5 for the full contract.

---

## UI Request Lifecycle

All UI routes follow the same lifecycle:

```
Request
  └─► auth.BearerMiddleware        # 401 if token missing or invalid
        └─► audit.LogRequest        # log every request (method, path, remote IP)
              └─► handler           # business logic
                    ├─► files.Backup()         # always before write
                    ├─► generate snippet       # pure function, no side effects
                    ├─► files.AtomicWrite()    # write temp → rename
                    ├─► caddy.Reload()         # POST /load to Admin API
                    ├─► audit.LogAction()      # structured audit entry
                    └─► respond                # 200 full-page re-render OR 500 with error (no HTMX)
```

On any failure after `files.Backup()`, the backup is preserved and the UI surfaces a rollback prompt.

---

## File Naming Convention

Domain names are normalized to a filesystem-safe slug:

```go
// api.example.com  →  api_example_com
// *.example.com    →  wildcard_example_com
func domainSlug(domain string) string {
    r := strings.NewReplacer(".", "_", "*", "wildcard", "-", "_")
    return r.Replace(strings.ToLower(domain))
}
```

File names:

| File | Purpose |
|---|---|
| `waf-{slug}.conf` | WAF engine mode + Coraza directive block |
| `exclusions-{slug}.conf` | All CRS exclusions for the domain |
| `ip-rules-{slug}.conf` | IP allowlist and denylist Caddy matchers |

Snapshot names (in `/backups/{slug}/`):

| File | Purpose |
|---|---|
| `{ISO8601}.waf.conf` | WAF conf snapshot |
| `{ISO8601}.exclusions.conf` | Exclusions conf snapshot |
| `{ISO8601}.ip-rules.conf` | IP rules conf snapshot |

---

## Security Boundaries

### Authentication (NIST AC-3)

- Single Bearer token configured via `CADDY_UI_TOKEN` environment variable
- Token is compared using `subtle.ConstantTimeCompare` to prevent timing attacks
- All unauthenticated requests return `401` with no body (no information leakage)
- Token is never logged, never echoed in responses

### Network isolation (NIST SC-7, AC-4)

- UI binds to `0.0.0.0:8080` by default (reachable on the Docker network); host exposure is restricted via the compose port mapping `127.0.0.1:8080:8080`
- If external access is needed, it goes through Caddy itself (acting as its own reverse proxy) with mTLS
- Caddy Admin API (`caddy:2019`) is reachable only within the Docker network - never exposed to host

### File write safety (NIST CM-3)

- All writes are **atomic**: write to `{file}.tmp` then `os.Rename()` - no partial writes visible to Caddy
- Backup is always taken **before** any write
- The UI validates user input with strict regexes before generating snippets (no output whitelist; snippets come only from internal generators)
- Domain names are validated at the service boundary: `service.ValidateDomain` enforces strict RFC 1035 hostnames (length, per-label charset, no leading/trailing dots, no `..`) before any use in paths, templates, or backups; invalid domains fail with the `ErrInvalidDomain` sentinel → `400 Bad Request` in the REST API

### Audit logging (NIST AU-12)

Every action emitted to stdout as JSON:

```json
{
  "ts": "2026-07-22T14:32:11Z",
  "level": "info",
  "event": "waf_mode_changed",
  "domain": "api.example.com",
  "from": "DetectionOnly",
  "to": "On",
  "remote_ip": "100.64.0.5",
  "caddy_reload": "success"
}
```

### Cloudflare token (NIST SC-28, planned - not implemented in MVP)

- Stored in `.env` (permissions `600`)
- Displayed in UI as `••••••••••••{last4}`
- Written to `.env` on update via atomic write
- Never appears in audit logs, access logs, or error responses

### Browser content security (CSP)

- All responses (pages, API, login, and assets) carry `Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` (see `internal/ui/static.go`)
- Frontend assets are **self-hosted and embedded in the binary** (`go:embed` → served under `/static/`, public, no auth): `pico.min.css` (Pico CSS v2.1.1, pinned - no CDN), `app.css`, and `app.js`
- Inline styles and inline event handlers are banned; `app.js` attaches behavior via `data-*` attributes (`data-dismiss-toast`, `data-confirm-off`, `data-confirm`), keeping `script-src 'self'` enforceable

---

## Architectural Decision Records

### ADR-001 - Go over FastAPI

**Decision:** Implement in Go, not Python/FastAPI.

**Rationale:** This project targets open source distribution. A Go binary requires no runtime, no pip, no venv - users `docker pull` and run. Build artifacts are single static binaries (~10MB). The project complexity (HTTP handlers + file I/O + HTTP client) does not justify a framework.

**Trade-off:** Slower initial development vs. FastAPI. Accepted.

---

### ADR-002 - Namespace isolation via ui-managed/ volume

**Decision:** The UI writes exclusively to a dedicated `ui-managed/` volume. The base Caddyfile is never touched.

**Rationale:** Preserves Ansible as the authority for base config. Limits blast radius of a compromised UI container to runtime WAF overrides only - no access to certs, base routing, or TLS configuration.

**Trade-off:** Requires the `import` directive in the Ansible Caddyfile template. One-time change, low risk.

---

### ADR-003 - Admin API for reload, not SIGHUP

**Decision:** Trigger Caddy reload via `POST http://caddy:2019/load` (Admin API), not via `kill -USR1` or container restart.

**Rationale:** The Admin API provides a structured response confirming whether the config was valid before applying. SIGHUP reloads apply the config regardless and surface errors only in logs. A failed Admin API reload leaves the previous config running - safer for production.

**Trade-off:** Requires `caddy_admin_enabled: true` on nodes with the UI. Documented as a required condition in prerequisites.

---

### ADR-004 - No database

**Decision:** No database. State is the filesystem.

**Rationale:** The managed config files in `ui-managed/` are the canonical state. Backups are files. Logs are files. A database would duplicate state and add a failure mode. The operator can inspect, copy, or restore state with standard Unix tools - no CLI or DB client required.

**Trade-off:** No query capabilities on historical data. Accepted for MVP; log aggregation (Grafana/ClickHouse) is out of scope.

---

### ADR-005 - IP rules at Caddy layer, not Coraza

**Decision:** IP allowlist/denylist uses Caddy native `remote_ip` matchers, not Coraza `SecRule REMOTE_ADDR`.

**Rationale:** Caddy evaluates matchers before routing - blocked IPs never reach the WAF engine, incurring zero Coraza overhead. Caddy matchers also support CIDR notation natively and are simpler to audit.

**Trade-off:** IP rules and WAF rules live in separate files for the same domain. Documented clearly in the UI.

---

### ADR-006 - Atomic writes only

**Decision:** Every file write follows write-to-temp-then-rename pattern.

**Rationale:** Caddy reads config files continuously. A partial write to a `.conf` file can result in a malformed import that crashes Caddy on the next reload. `os.Rename()` is atomic on Linux (same filesystem) - Caddy never sees a partial file.

**Implementation:**
```go
func atomicWrite(path string, content []byte) error {
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, content, 0644); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}
```
