// Package config centralizes environment-based configuration reads
// (convention D2): the variable names and their defaults live in a single
// place instead of being repeated per package (finding J5-3). The defaults
// are identical to the historical ones: /ui-managed, /backups,
// /data/logs/coraza-audit.log.
//
// Each helper deliberately re-reads the environment on EVERY call:
// configuration is read per request (decision D2), and tests change variables
// per test with t.Setenv. A sync.Once cache would freeze the first value read
// and break both contracts.
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

// envOr returns the value of the key variable, or fallback if it is empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ManagedDir returns CADDY_UI_MANAGED_DIR (default /ui-managed): the
// directory where the UI writes the managed overlays.
func ManagedDir() string {
	return envOr("CADDY_UI_MANAGED_DIR", defaultManagedDir)
}

// BackupDir returns CADDY_UI_BACKUP_DIR (default /backups): the root of the
// configuration snapshots.
func BackupDir() string {
	return envOr("CADDY_UI_BACKUP_DIR", defaultBackupDir)
}

// BackupKeep returns CADDY_UI_BACKUP_KEEP (default 10): the snapshot
// retention limit per domain and type.
func BackupKeep() int {
	if k, err := strconv.Atoi(os.Getenv("CADDY_UI_BACKUP_KEEP")); err == nil && k > 0 {
		return k
	}
	return defaultBackupKeep
}

// AuditLogPath returns CADDY_UI_AUDIT_LOG (default
// /data/logs/coraza-audit.log): the Coraza audit log read by the explorer.
func AuditLogPath() string {
	return envOr("CADDY_UI_AUDIT_LOG", defaultAuditLog)
}

// CaddyfilePath returns CADDY_UI_CADDYFILE (default /etc/caddy/Caddyfile):
// the Caddyfile sent to the Admin API on each reload.
func CaddyfilePath() string {
	return envOr("CADDY_UI_CADDYFILE", defaultCaddyfile)
}

// AdminURL returns CADDY_ADMIN_URL (default http://caddy-waf:2019): Caddy's
// Admin API.
func AdminURL() string {
	return envOr("CADDY_ADMIN_URL", defaultAdminURL)
}

// IncludeDir returns CADDY_UI_INCLUDE_DIR (default /etc/caddy/ui-managed):
// Caddy's view of the overlays directory, used in the Include directive of
// the generated overlays (finding J5-1). It is independent of ManagedDir: the
// UI and Caddy mount the same volume at different points of each container's
// filesystem (INTEGRATION.md §3).
func IncludeDir() string {
	return envOr("CADDY_UI_INCLUDE_DIR", defaultIncludeDir)
}

// BindAddr returns CADDY_UI_BIND (default 0.0.0.0:8080): the listen address
// of the UI's HTTP server.
func BindAddr() string {
	return envOr("CADDY_UI_BIND", defaultBindAddr)
}

// LogLevel returns CADDY_UI_LOG_LEVEL (default "info"): the logger level.
func LogLevel() string {
	return envOr("CADDY_UI_LOG_LEVEL", defaultLogLevel)
}

// Token returns CADDY_UI_TOKEN (empty when unset: the session middleware
// blocks all access without a valid token).
func Token() string {
	return os.Getenv("CADDY_UI_TOKEN")
}
