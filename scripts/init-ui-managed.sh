#!/bin/sh
# Inicializador de overlays ui-managed para el stack (servicio ui-config-init).
#
# El Caddyfile importa overlays per-slug desde /etc/caddy/ui-managed/*.conf
# (p.ej. ip-rules-{slug}.conf, waf-{slug}.conf). Esos archivos solo los
# escribe la UI en runtime, pero viven en el volumen named caddy-ui-config:
# si el volumen se recrea (down -v / primer arranque), Caddy no arranca por
# imports faltantes. Este init repara esa dependencia de arranque.
#
# Reglas de diseño (importantes para producción):
#   1. Idempotente: crea SOLO los archivos faltantes ([ -f ] || crear).
#   2. NUNCA sobrescribe configs existentes - los overlays de dominios/apps
#      en producción son datos de runtime y se preservan intactos.
#   3. Descubre los imports desde el Caddyfile montado (no hardcodea nada):
#      en producción recrea únicamente los overlays de los dominios/apps que
#      el Caddyfile real declara.
#   4. Corre como uiuser (mismo uid que la UI): los archivos creados quedan
#      con ownership de la UI, que puede sobrescribirlos siempre (atomic
#      write vía rename). Caddy (uid 1337) los lee por ser world-readable.
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
