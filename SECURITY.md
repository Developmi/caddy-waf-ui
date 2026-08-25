# Security Policy - caddy-waf-ui

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x (latest: v1.0.0) | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report via:
- GitHub Security Advisory: [New Advisory](https://github.com/Developmi/caddy-waf-ui/security/advisories/new)
- Email: miguel@developmi.com (include `[SECURITY]` in subject)

Include in your report:
- Description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- Affected versions.
- Any suggested mitigations.

### Response timeline

| Stage | Target |
|---|---|
| Acknowledgment | 48 hours |
| Triage and severity assessment | 5 business days |
| Fix and coordinated disclosure | 30 days (critical), 90 days (others) |

## Disclosure Policy

This project follows **coordinated disclosure**. We ask that you give us reasonable time to address the vulnerability before public disclosure:

- **Critical issues:** fix or mitigation targeted within 7 days; disclosure only after the fix is available.
- **Other issues:** disclosure no earlier than the fix or mitigation, within the 30/90-day response window.

We will credit reporters in the release notes unless anonymity is requested.

## Scope

In-scope for this project:

- Authentication bypass or token leakage
- Arbitrary file write outside `ui-managed/` volume
- Token or secret exposure in logs or HTTP responses
- Directory traversal in file path construction
- SSRF via Caddy Admin API URL parameter

Out of scope:

- Vulnerabilities in Caddy, Coraza, or OWASP CRS (report to their respective projects)
- Issues requiring physical access to the host
- Social engineering

## Supply Chain Verification

Images are signed with Cosign (keyless, GitHub OIDC):

```bash
cosign verify \
  --certificate-identity "https://github.com/Developmi/caddy-waf-ui/.github/workflows/docker-build-scan-sign.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/developmi/caddy-waf-ui@sha256:<digest>
```

Always pull by digest in production. Do not use `:latest` in production compose files.

## Caddy Admin API - Residual Risk (contract §6)

The UI reloads Caddy through `POST /load` on the Admin API (`CADDY_ADMIN_URL`,
default `http://caddy-waf:2019`). **The Admin API call carries no credentials**:
Caddy's plaintext admin endpoint has no built-in authentication, and this UI
does not (yet) present a client certificate.

Accepted residual risk - until the mTLS target (cross-project contract §6,
caddy-waf ROADMAP items 6–7) is implemented, the deployment MUST enforce all
of these compensating controls:

1. **Network isolation only**: the Admin API is reachable only over the
   internal Docker network (never host-published; compose publishes 80/443
   only). The admin endpoint binds inside the container network
   (`admin 0.0.0.0:2019 { enforce_origin }`), never on the host - see the
   compose + bind-mount deployment model in [INTEGRATION.md](./INTEGRATION.md).
2. **Platform default is `admin off`** (AC-3): `caddy_admin_enabled` is
   `false` unless the UI is actually deployed; when enabled, the rendered
   admin block is `admin 0.0.0.0:2019 { enforce_origin }` inside the container
   network, never published to the host.
3. **Host firewall denies 2019/2020** on all interfaces (stack L2 UFW/nftables
   rules) and a fail-safe assert forbids those ports in `allowed_ports`.
4. **`CADDY_ADMIN_URL` is operator-set and must point at the internal
   address**; it is never exposed to end users.
5. **Read-back verification (D3)**: after every `POST /load` the UI verifies
   the live config via `GET /config/apps/http/servers`; a mismatch fails loud
   and triggers the overlay rollback path - a compromised reload cannot
   silently disable the WAF without being reported.

Any deployment that cannot enforce controls 1–4 must NOT enable the UI.
The mTLS target (identity + `access_control` public keys on Caddy's remote
admin listener, UI client certificate) removes the reliance on network
placement alone.

## Known Limitations - Auth Notes & Rate Limiting

Documented design decisions, not defects:

- **Logout is client-side only.** The session token is stateless: a
  high-entropy bearer token compared in constant time
  (`subtle.ConstantTimeCompare`), with no server-side session store. Logout
  clears the cookie but **cannot revoke or expire tokens already issued** -
  anyone who captured a valid token keeps using it until the service
  redeploys with a rotated `CADDY_UI_TOKEN`. This is the accepted trade-off
  of a single-operator admin console: treat the token as full admin access
  and rotate it when it may have been exposed.
- **No rate limiting on `/login` or the API.** Brute force is mitigated by
  constant-time token comparison plus a high-entropy token, not by
  throttling. Rate limiting is intentionally left to the deployment layer:
  Caddy (e.g. the `rate_limit` directive) or the reverse proxy in front of
  the UI.
