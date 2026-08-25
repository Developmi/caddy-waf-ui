# Integration Contract - caddy-waf-ui · caddy-waf · stack (Ansible)

This document is the authoritative contract for deploying `caddy-waf-ui` alongside
`caddy-waf` in the `stack` (Ansible) infrastructure. It defines how the three
repositories cooperate, what each channel is allowed to change, and the operational
procedures (emergency change, drift, onboarding) that keep the system safe.

Audience: operators and maintainers of the `stack` and `caddy-waf-ui` repositories.

---

## 1. Overview - two-channel model

WAF configuration is deliberately split across two independent channels with a
**clear authority boundary** (NIST CM-3a):

| Concern | Channel | Owner | How it changes |
|---------|---------|-------|----------------|
| Site identity (domains, TLS, certificates, routing) | GitOps | `stack` (Ansible + vault + PR) | Infrastructure-as-Code render, reviewed PRs |
| Default WAF posture (`waf_mode` baseline) | GitOps | `stack` (vault) | Vault value → rendered into the base Caddyfile |
| Runtime WAF deltas (mode, exclusions, IP rules) | UI | `caddy-waf-ui` | Overlay files under `/etc/caddy/ui-managed/`, hot reload via the Admin API |
| Emergency IP block (active attack) | UI | `caddy-waf-ui` | Immediate overlay write + reload, followed by retrospective approval (§8) |

- **GitOps owns identity and baseline.** The base Caddyfile is Ansible-owned,
  mounted read-only into the Caddy container, and never written by the UI.
- **The UI owns runtime deltas only.** It writes exclusively to the
  `ui-managed` overlay directory (per-slug files, §5) and triggers Caddy reloads
  through the Admin API (§4). It has no access to the base Caddyfile, the vault,
  or the certificate material.
- **An IP block is an emergency change** (§8): it takes effect immediately
  through the UI - it must not wait for a pipeline - and is then approved
  retrospectively and promoted to IaC.

This two-channel split is what lets operators tune the WAF at runtime without
granting write access to the Ansible inventory, and without turning every tuning
action into a PR cycle.

---

## 2. Repositories

| Repository | Role | Touch rules |
|------------|------|-------------|
| `caddy-waf` | Base image and packaging (Caddy + Coraza, entrypoint, image defaults) | **Do NOT modify** from `caddy-waf-ui` or `stack`. Optional improvement only: declare `/etc/caddy/ui-managed` in its Dockerfile (§3, requires image rebuild). |
| `stack` | Ansible IaC: inventory, vault, role templates, Caddyfile.j2, host provisioning | Owns site identity and baseline (§1). Must create overlay placeholders (§5) and production mounts (§3). Never writes overlay **content** - UI owns it. |
| `caddy-waf-ui` | This repository: sidecar management UI + overlay generators | Writes `/etc/caddy/ui-managed/{waf,exclusions,ip-rules}-{slug}.conf` only. Ships the contract you are reading. |

---

## 3. Mounts - dev vs production

### Development (this repository, `docker-compose.yml`)

A named volume `caddy-ui-config` is shared by both containers:

- `caddy-waf`: `caddy-ui-config:/etc/caddy/ui-managed:ro` - read-only, Caddy can never modify overlays.
- `caddy-waf-ui`: `caddy-ui-config:/ui-managed:rw` - the UI writes overlays here.
- `caddy-waf-ui` also mounts `./Caddyfile:/etc/caddy/Caddyfile:ro` (the reload source, §9).

The one-shot `ui-config-init` service (same image and user as the UI) creates the
overlay files that the Caddyfile imports before Caddy starts - idempotent, it
**never overwrites** existing configs. It runs as `uiuser` (uid 1000, the same
uid as the UI), so the UI can always overwrite them later. No manual chown or
init step is needed on a fresh volume: `docker compose up -d` boots the stack.

### Production (stack)

Production uses **bind mounts** - the stack's natural model, no named volumes:

1. The Ansible role creates the host directory `ui-managed` owned by
   `1337:1337` (the Caddy container UID).
2. The stack mounts it **read-only** into `caddy-waf` at `/etc/caddy/ui-managed`.
3. The UI sidecar (bind-mounting the same host directory read-write) writes
   overlays that Caddy then reads.

**Zero init in production**: because Ansible pre-creates the directory with the
correct owner, no chown step is ever needed.

### File mode

Overlays are written `0644` (world-readable) **by design**: the Caddy container
runs as `1337:1337` and is not in the UI user's group; `0640` would make overlays
unreadable and break the reload. Overlays contain **no secrets** - only WAF
runtime directives. Do not re-tighten the mode.

### Audit log contract - `caddy_data:/data:ro`

The UI reads the Coraza audit log (`CADDY_UI_AUDIT_LOG`, default
`/data/logs/coraza-audit.log`) through the shared `caddy_data` volume mounted
**read-only** (`:ro`). The UI container runs as `uiuser` (uid 1000) while Caddy
writes the log as uid 1337, so the contract depends on file/directory modes set
by the sibling image:

- **Verified against `ghcr.io/developmi/caddy-waf:v3.3.2`** (running stack):
  `/data/logs` is `drwxr-xr-x` and `coraza-audit.log` is `-rw-r--r--` (0644) -
  world-readable, so uid 1000 can open it. No action needed in this repo.
- **Required invariant (stack/sibling image)**: the audit log must stay `0644`
  (or the directory at least `0755`). If the sibling image ever tightens these
  modes (e.g. `0600`), the UI log viewer silently loses visibility - the
  contract must be kept on the caddy-waf side, not papered over here.

### Optional improvement (caddy-waf image)

Declare `/etc/caddy/ui-managed` in the `caddy-waf` Dockerfile
(`mkdir -p /etc/caddy/ui-managed && chown 1337:1337 /etc/caddy/ui-managed`).
This makes named-volume dev setups work without the init step. Requires an image
rebuild; purely optional.

---

## 4. Admin API - `caddy_admin_enabled`

The Caddy Admin API (`POST /load`) is the hot-reload mechanism the UI depends on.
It is also a powerful control plane - access must be tightly constrained (AC-3, SC-7).

- **Default OFF in the stack.** The Admin API is only enabled when
  `caddy-waf-ui` is actually deployed on the node.
- **Enable explicitly**: set `caddy_admin_enabled: true` in the stack's vars
  (or the variable the stack uses for this), and only on nodes running the UI.
- **Restrictions (mandatory when ON)**:
  - Internal network only: unix socket or `localhost`/Docker-internal binding.
    Never publish the admin port to the host (`docker-compose` here publishes
    only 80/443; keep it that way).
  - `enforce_origin` enabled on the admin endpoint to prevent DNS-rebinding
    attacks; restrict allowed origins to the UI's internal address.
  - SSRF mitigation: the UI's `CADDY_ADMIN_URL` must point at the internal
    address; the admin endpoint must not be reachable from untrusted networks.
- References: NIST SP 800-53 AC-3 (access control), SC-7 (boundary protection);
  Caddy Admin API docs (https://caddyserver.com/docs/api) and the `admin`
  global option (https://caddyserver.com/docs/caddyfile/options#admin).

### Trust boundary - `admin 0.0.0.0:2019` without origins

The example Caddyfile in this repo exposes the Admin API as
`admin 0.0.0.0:2019` **without an `origins` list** (the Caddyfile is
user-owned and gitignored - it is not modified here). Consequences and
mitigations, for the operator to evaluate against the threat model:

- **Every container on the `caddy-network` bridge can call the Admin API**,
  including `POST /load` (full config replacement) - not just the UI.
  Untrusted containers must never share this network.
- The port is **not published to the host** (compose exposes only 80/443 and
  the UI's loopback bind), so the exposure is Docker-internal only.
- **Mitigations if the threat model demands more** (any combination):
  - `admin 0.0.0.0:2019 { origins http://caddy-waf-ui:8080 }` - restricts
    accepted `Origin`/`Host` headers to the UI (Caddy 2.10+).
  - Restrict the listener to a dedicated internal interface or an
    `internal:` network ACL (Docker network segmentation).
  - Bearer auth on the Admin API itself (custom matcher on `/admin/*`).
- NIST mapping: SC-7 (boundary protection) - the Docker bridge is the
  boundary; everything on it is in the same trust domain.

---

## 5. Imports per-slug - the overlay wiring contract

Inside **UI-managed site blocks** the Caddyfile imports exactly two overlay files,
in this order:

```caddyfile
api.example.com {
    import /etc/caddy/ui-managed/ip-rules-api_example_com.conf
    import /etc/caddy/ui-managed/waf-api_example_com.conf
    ...
}
```

Contract rules:

- **Order**: `ip-rules-{slug}.conf` **first** (IP rules run before the WAF -
  blocked traffic never reaches Coraza), then `waf-{slug}.conf`.
- **No `import waf` in managed blocks.** The overlay already contains an inline
  `coraza_waf { ... }` block; importing the base `(waf)` snippet too would
  instantiate a second engine and break the reload.
- **Exclusions enter only through the Coraza internal `Include`** - the
  generated overlay embeds `Include {CADDY_UI_INCLUDE_DIR}/exclusions-{slug}.conf`
  (default `/etc/caddy/ui-managed`, the Caddy-side view of the overlay volume;
  the UI writes to `CADDY_UI_MANAGED_DIR`, a different mount point in its own
  container - see §3) inside its `coraza_waf` block. Exclusions are **never**
  imported from the Caddyfile.
- **Unmanaged domains keep `import waf`** - the base snippet, default posture
  `SecRuleEngine DetectionOnly`.

### Placeholders - the Ansible role MUST pre-create them

A **specific** import whose file does not exist **hard-fails Caddy startup**
(verified; there is no silent skip for specific imports - only non-matching
*globs* warn). Therefore, for every managed domain, the Ansible role must
pre-create, **before first boot**, empty placeholder files:

```
/etc/caddy/ui-managed/waf-{slug}.conf
/etc/caddy/ui-managed/ip-rules-{slug}.conf
```

- The role creates them **idempotently** (missing → create empty; present → leave untouched).
- It must **never overwrite** placeholder content - once the UI writes an
  overlay, the file is UI-owned.
- `exclusions-{slug}.conf` needs no placeholder: it is reached via the Coraza
  internal `Include`, which tolerates absence.

### Slug

`slug = domain.DomainSlug(domain)`: lowercase; `.` → `_`; `*` → `wildcard`;
`-` → `_`. Examples: `api.example.com` → `api_example_com`,
`*.example.com` → `wildcard_example_com`. This matches the example Caddyfiles
shipped in this repository.

---

## 6. `waf_mode` - vault baseline vs UI overlay

- In UI-managed domains, the **runtime mode is decided by the overlay** - i.e.
  by the UI. The vault value (`waf_mode`) keeps the **default posture**
  (baseline: `DetectionOnly`) used by unmanaged domains and by the placeholders
  before the UI first writes.
- **Do not edit the overlay mode from the vault** for UI-managed domains: the
  next UI action overwrites it, and direct vault edits create drift (§7).
- **Promotion path**: stable exclusion sets (and validated mode changes) are
  promoted to the baseline via a **reviewed PR** (A.8.9) - e.g. baking
  exclusions into `crs-setup.conf`/the role defaults, or flipping the vault
  default once the runtime tuning is proven.

---

## 7. Drift sync

The UI-owned overlays are outside the IaC render path - Caddy applies them via
ordered imports, they are **not** templated by Ansible. That makes drift between
"what GitOps thinks" and "what runs" possible; detect it:

- **Periodic check**: `ansible-playbook --check --diff` (or a scheduled
  comparison of the rendered Caddyfile vs the live one) with an **alert on
  divergence** (CM-6d, A.8.9, CSF PR.PS-01).
- **Scope**: drift review covers the base Caddyfile and vault-derived settings.
  Overlay content is expected to differ from the baseline by design (§6).
- **The reconciler NEVER writes to `/etc/caddy/ui-managed/*`** - those files are
  owned by the UI at runtime. An Ansible task that templates or restores them
  would fight the UI and must not exist.

---

## 8. Emergency change procedure - blocking an IP under attack

Blocking an attacker IP is an **emergency change** (SP 800-128 emergency
changes; SP 800-40 emergency workarounds; ITIL ECAB):

1. **Immediate**: operator blocks the IP from the UI (denylist → immediate
   overlay write → `POST /load`). **No pipeline wait.**
2. **Retrospective approval**: within ≤ 24h, the change is documented and
   approved retrospectively; a Post-Implementation Review (PIR) captures what
   happened and why.
3. **Promotion**: the permanent fix (e.g. tightening rules, rate limiting) is
   promoted to IaC via a normal reviewed PR; the emergency denylist entry is
   reviewed for removal once the threat is over.

Anti-abuse discipline: emergency powers are for genuine attacks; routine tuning
uses the normal (non-emergency) change path.

---

## 9. Onboarding - registering a new managed domain

1. **Ansible alta**: add the domain to the stack - site block with the §5
   per-slug imports, the two placeholder files, and the Cloudflare client
   certificates in the vault - then deploy.
2. **Discovery**: the UI discovers the domain either via its
   `waf-{slug}.conf` (scanner) or on the first UI write.
3. **Manage**: the operator manages mode, exclusions, and IP rules from the UI.
4. **Apply**: changes take effect via `Reload()` - the UI reads the base
   Caddyfile (`CADDY_UI_CADDYFILE`, default `/etc/caddy/Caddyfile`) and sends it
   to `POST /load` as `text/caddyfile` (10s timeout). **The UI never writes the
   Caddyfile; it re-sends it** to trigger Caddy's reload.

---

## 10. Compensating controls

Because the UI holds runtime write authority over WAF behavior, the following
controls compensate for that authority (from exploration #299). Each row states
what exists **today in this repository** vs what the **stack must provide** or
what is **roadmap**.

| # | Control | Normative references | This repo today | Stack / roadmap |
|---|---------|----------------------|-----------------|-----------------|
| 1 | Admin API locked down: internal network only, `enforce_origin`, bearer auth | SC-7, AC-3 | UI calls `caddy:2019` over the Docker-internal network only; admin port never published to the host; bearer token auth on all UI routes | Stack: `caddy_admin_enabled` default OFF; when ON, bind internal-only and enable `enforce_origin` (§4) |
| 2 | Least-privilege, revocable tokens; re-auth for high-impact actions; session timeout ≤ 15 min | A.8.2, AC-12, CIS 4.3 | Bearer token auth (constant-time compare); HttpOnly/Secure/SameSite=Strict cookie session; HMAC-CSRF on every form | Stack: token management/rotation in vault; roadmap: re-auth for high-impact actions, explicit session timeout |
| 3 | Immutable, append-only audit trail outside operator reach | AU-11, AU-12, CM-3f, A.8.15 | **STACK/ROADMAP - NOT implemented today.** UI logs structured JSON actions (actor, timestamp, action, domain) to stdout only | Roadmap: ship logs to an append-only store the operator cannot truncate |
| 4 | Monitoring with alerts on WAF activity and drift | A.8.16, AU-6 | UI surfaces Coraza detections in the log viewer | Stack/roadmap: SIEM ingestion + alert rules (also §7 drift alert) |
| 5 | Authority boundary + emergency change with post-approval | CM-3a, SP 800-128, ITIL ECAB | Two-channel model (§1) and emergency procedure (§8) documented here; UI allows immediate IP blocks | Stack: retrospective approval workflow (≤ 24h + PIR) |
| 6 | Overlays versioned, rollback available, post-change validation | CM-3(2), A.8.32 | Snapshot taken before every write (up to `CADDY_UI_BACKUP_KEEP` per domain); read-back verification (GET /config/apps/http/servers) after each reload (D3) | Implemented: rollback UI (rollback.html + POST /api/sites/{domain}/rollback) restores snapshot + reloads |
| 7 | Drift sync with alert | CM-6d, A.8.9 | Overlays out of IaC render scope by design (§7) | Stack: periodic `ansible-playbook --check --diff` + alert on divergence |
| 8 | Periodic review and promotion of stable changes | A.8.9 | - | Stack: review cadence that promotes stable exclusions/modes to baseline via PR (§6) |

**Status legend**: rows marked "STACK/ROADMAP" are deliberately **not claimed as
implemented in this repository** - they are deployment-side responsibilities or
future work, and this document must not be read as claiming them.
