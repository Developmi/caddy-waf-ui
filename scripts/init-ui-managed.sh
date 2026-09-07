#!/bin/sh
# ui-managed overlays initializer for the stack (ui-config-init service).
#
# The Caddyfile imports per-slug overlays from /etc/caddy/ui-managed/*.conf
# (e.g. ip-rules-{slug}.conf, waf-{slug}.conf). Those files are only written
# by the UI at runtime, but they live in the caddy-ui-config named volume:
# if the volume is recreated (down -v / first boot), Caddy fails to start
# because of missing imports. This init repairs that boot dependency.
#
# Design rules (important for production):
#   1. Idempotent: creates ONLY the missing files ([ -f ] || create).
#   2. NEVER overwrites existing configs - the domain/app overlays in
#      production are runtime data and are preserved intact.
#   3. Discovers the imports from the mounted Caddyfile (nothing hardcoded):
#      in production it recreates only the overlays of the domains/apps that
#      the real Caddyfile declares.
#   4. Runs as uiuser (same uid as the UI): the created files keep the UI's
#      ownership, so the UI can always overwrite them (atomic write via
#      rename). Caddy (uid 1337) reads them because they are world-readable.
set -eu

SRC=/etc/caddy/Caddyfile
[ -f "$SRC" ] || SRC=/etc/caddy/Caddyfile.example

for f in $(grep -oE 'import /etc/caddy/ui-managed/[^ ]+\.conf' "$SRC" | sed 's#import /etc/caddy/ui-managed/##' | sort -u); do
  if [ -f "/ui-managed/$f" ]; then
    echo "init: exists, skipping /ui-managed/$f"
  else
    printf '# Caddy WAF UI managed - do not edit manually\n' > "/ui-managed/$f"
    echo "init: created /ui-managed/$f"
  fi
done

exit 0
