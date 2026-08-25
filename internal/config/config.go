// Package config centraliza la lectura de configuración por entorno
// (convención D2): los nombres de variable y sus defaults viven en un único
// lugar en lugar de repetirse por paquete (hallazgo J5-3). Los defaults son
// idénticos a los históricos: /ui-managed, /backups, /data/logs/coraza-audit.log.
//
// Cada helper relee el entorno en CADA llamada a propósito: la configuración
// se lee por request (decisión D2) y los tests cambian variables por test con
// t.Setenv. Un caché con sync.Once congelaría el primer valor leído y rompería
// ambos contratos.
package config

import (
	"os"
	"strconv"
)

const (
	defaultManagedDir = "/ui-managed"
	defaultBackupDir  = "/backups"
	defaultBackupKeep = 10
	defaultAuditLog   = "/data/logs/coraza-audit.log"
	defaultCaddyfile  = "/etc/caddy/Caddyfile"
	defaultAdminURL   = "http://caddy-waf:2019"
	defaultBindAddr   = "0.0.0.0:8080"
	defaultLogLevel   = "info"
	defaultIncludeDir = "/etc/caddy/ui-managed"
)

// envOr devuelve el valor de la variable key, o fallback si está vacía.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ManagedDir devuelve CADDY_UI_MANAGED_DIR (default /ui-managed): el
// directorio donde la UI escribe los overlays gestionados.
func ManagedDir() string {
	return envOr("CADDY_UI_MANAGED_DIR", defaultManagedDir)
}

// BackupDir devuelve CADDY_UI_BACKUP_DIR (default /backups): la raíz de los
// snapshots de configuración.
func BackupDir() string {
	return envOr("CADDY_UI_BACKUP_DIR", defaultBackupDir)
}

// BackupKeep devuelve CADDY_UI_BACKUP_KEEP (default 10): el límite de
// retención de snapshots por dominio y tipo.
func BackupKeep() int {
	if k, err := strconv.Atoi(os.Getenv("CADDY_UI_BACKUP_KEEP")); err == nil && k > 0 {
		return k
	}
	return defaultBackupKeep
}

// AuditLogPath devuelve CADDY_UI_AUDIT_LOG (default
// /data/logs/coraza-audit.log): el audit log de Coraza que lee el explorador.
func AuditLogPath() string {
	return envOr("CADDY_UI_AUDIT_LOG", defaultAuditLog)
}

// CaddyfilePath devuelve CADDY_UI_CADDYFILE (default /etc/caddy/Caddyfile):
// el Caddyfile que se envía a la Admin API en cada recarga.
func CaddyfilePath() string {
	return envOr("CADDY_UI_CADDYFILE", defaultCaddyfile)
}

// AdminURL devuelve CADDY_ADMIN_URL (default http://caddy-waf:2019): la
// Admin API de Caddy.
func AdminURL() string {
	return envOr("CADDY_ADMIN_URL", defaultAdminURL)
}

// IncludeDir devuelve CADDY_UI_INCLUDE_DIR (default /etc/caddy/ui-managed):
// la vista de CADDY del directorio de overlays, usada en la directiva Include
// de los overlays generados (hallazgo J5-1). Es independiente de ManagedDir:
// la UI y Caddy montan el mismo volumen en puntos distintos del sistema de
// archivos de cada contenedor (INTEGRATION.md §3).
func IncludeDir() string {
	return envOr("CADDY_UI_INCLUDE_DIR", defaultIncludeDir)
}

// BindAddr devuelve CADDY_UI_BIND (default 0.0.0.0:8080): la dirección de
// escucha del servidor HTTP de la UI.
func BindAddr() string {
	return envOr("CADDY_UI_BIND", defaultBindAddr)
}

// LogLevel devuelve CADDY_UI_LOG_LEVEL (default "info"): el nivel del logger.
func LogLevel() string {
	return envOr("CADDY_UI_LOG_LEVEL", defaultLogLevel)
}

// Token devuelve CADDY_UI_TOKEN (vacío si no está configurado: el middleware
// de sesión bloquea todo acceso sin token válido).
func Token() string {
	return os.Getenv("CADDY_UI_TOKEN")
}
