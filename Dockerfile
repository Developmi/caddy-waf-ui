# Etapa 1: Construcción (Builder)
# Pin exacto del toolchain: go.mod declara go 1.26.6 (GOTOOLCHAIN=auto no descarga
# versiones en cada build - reproducibilidad, no float).
FROM golang:1.26.6-alpine AS builder

# Habilitar Go modules y configurar el directorio
ENV GO111MODULE=on
WORKDIR /app

# Copiar el archivo de módulo 
COPY go.mod ./
# Si más adelante agregas dependencias y se genera un go.sum, descomenta la siguiente línea:
# COPY go.sum ./
RUN go mod download

# Copiar el resto del código fuente
COPY . .

# Compilar el binario estático
# CGO_ENABLED=0 garantiza que el binario no dependa de librerías dinámicas de C
# -ldflags="-w -s" reduce el tamaño del binario eliminando información de debug
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o caddy-waf-ui ./cmd/server/

# Etapa 2: Imagen Final (Runtime)
# Alpine 3.23.5: misma línea que la base de caddy:2.11.4 (imagen caddy-waf v3.3.2).
# NUNCA usar :latest - pin inmutado, alineado con el ecosistema.
FROM alpine:3.23.5

# Metadatos OCI estáticos (supply chain: trazan el origen y la licencia del artefacto)
LABEL org.opencontainers.image.title="caddy-waf-ui"
LABEL org.opencontainers.image.description="Self-hosted sidecar management UI for caddy-waf: per-site WAF mode, CRS exclusions, IP rules, log viewer, and rollback"
LABEL org.opencontainers.image.source="https://github.com/developmi/caddy-waf-ui"
LABEL org.opencontainers.image.licenses="MIT"

# Instalar certificados raíz y datos de zona horaria (útil para logs y llamadas a la API de Cloudflare),
# crear el usuario no root de la UI y los directorios gestionados con ownership del usuario:
# los named volumes heredan el ownership del directorio en el primer montaje, evitando errores de
# permisos (EACCES) en ui-managed/ y backups/. Versiones de paquetes pineadas (DL3018).
RUN apk --no-cache add ca-certificates=20260611-r0 tzdata=2026c-r0 \
    && adduser -D -g '' uiuser \
    && mkdir -p /ui-managed /backups \
    && chown -R uiuser:uiuser /ui-managed /backups

USER uiuser

WORKDIR /app

# Traer el binario compilado desde la etapa anterior
COPY --from=builder --chown=uiuser:uiuser /app/caddy-waf-ui .

# Exponer el puerto por defecto de la UI
EXPOSE 8080

# Healthcheck: GET /health es público (sin auth) - wget de busybox está en alpine.
# wget devuelve exit != 0 si no conecta, lo que marca el contenedor unhealthy.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]

# Punto de entrada
CMD ["./caddy-waf-ui"]