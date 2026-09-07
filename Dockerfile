# Stage 1: Build (builder)
# Exact toolchain pin: go.mod declares go 1.26.6 (GOTOOLCHAIN=auto does not
# download versions on each build - reproducibility, no float).
FROM golang:1.26.6-alpine AS builder

# Enable Go modules and configure the working directory
ENV GO111MODULE=on
WORKDIR /app

# Copy the module file
COPY go.mod ./
# If you add dependencies later and a go.sum is generated, uncomment the next line:
# COPY go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the static binary
# CGO_ENABLED=0 ensures the binary does not depend on dynamic C libraries
# -ldflags="-w -s" reduces the binary size by stripping debug information
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o caddy-waf-ui ./cmd/server/

# Stage 2: Final image (runtime)
# Alpine 3.23.5: same line as the caddy:2.11.4 base (caddy-waf v3.3.2 image).
# NEVER use :latest - immutable pin, aligned with the ecosystem.
FROM alpine:3.23.5

# Static OCI metadata (supply chain: trace the artifact origin and license)
LABEL org.opencontainers.image.title="caddy-waf-ui"
LABEL org.opencontainers.image.description="Self-hosted sidecar management UI for caddy-waf: per-site WAF mode, CRS exclusions, IP rules, log viewer, and rollback"
LABEL org.opencontainers.image.source="https://github.com/developmi/caddy-waf-ui"
LABEL org.opencontainers.image.licenses="MIT"

# Install root certificates and timezone data (useful for logs and Cloudflare API calls),
# create the UI non-root user and the managed directories with user ownership:
# named volumes inherit the directory ownership on first mount, avoiding permission
# errors (EACCES) in ui-managed/ and backups/. Pinned package versions (DL3018).
#
# TRANSITIONAL PIN — openssl=3.5.8-r0 removes CVE-2026-14456 (OpenSSL 3.5.7-r0 → 3.5.8-r0; the
# fixed version is already available in APKINDEX v3.23/main and v3.24/main). REMOVE this pin
# once alpine 3.23.6 or 3.24.2 publish the fixed version.
RUN apk --no-cache add ca-certificates=20260611-r0 openssl=3.5.8-r0 tzdata=2026c-r0 \
    && adduser -D -g '' uiuser \
    && mkdir -p /ui-managed /backups \
    && chown -R uiuser:uiuser /ui-managed /backups

USER uiuser

WORKDIR /app

# Copy the compiled binary from the previous stage
COPY --from=builder --chown=uiuser:uiuser /app/caddy-waf-ui .

# Expose the default UI port
EXPOSE 8080

# Healthcheck: GET /health is public (no auth) - busybox wget ships in alpine.
# wget returns exit != 0 when it cannot connect, which marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]

# Entry point
CMD ["./caddy-waf-ui"]