package files_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// TestDomainSlug vive en internal/domain/slug_test.go (la función se movió a
// la frontera pure-domain, hallazgo J5-5); este archivo conserva los tests de
// las rutas derivadas del slug.

func TestBackupDirPath(t *testing.T) {
	tests := []struct {
		name      string
		backupDir string
		domain    string
		expected  string
	}{
		{"Dominio normal", "/backups", "api.example.com", "/backups/api_example_com"},
		{"Dominio con comodín", "/backups", "*.example.com", "/backups/wildcard_example_com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := files.BackupDirPath(tt.backupDir, tt.domain)
			if result != filepath.Clean(tt.expected) {
				t.Errorf("BackupDirPath(%q, %q) = %q; se esperaba %q", tt.backupDir, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestOverlayPath(t *testing.T) {
	tests := []struct {
		fileType string
		expected string
	}{
		{"waf", "/ui-managed/waf-api_example_com.conf"},
		{"exclusions", "/ui-managed/exclusions-api_example_com.conf"},
		{"ip-rules", "/ui-managed/ip-rules-api_example_com.conf"},
	}

	for _, tt := range tests {
		t.Run(tt.fileType, func(t *testing.T) {
			result, err := files.OverlayPath("/ui-managed", tt.fileType, "api.example.com")
			if err != nil {
				t.Fatalf("OverlayPath(%q) falló: %v", tt.fileType, err)
			}
			if result != filepath.Clean(tt.expected) {
				t.Errorf("OverlayPath(%q) = %q; se esperaba %q", tt.fileType, result, tt.expected)
			}
		})
	}

	// Tipo desconocido → error explícito (fail-loud).
	if _, err := files.OverlayPath("/ui-managed", "caddyfile", "api.example.com"); err == nil {
		t.Error("OverlayPath con tipo desconocido debe fallar")
	}
}

// TestBackupDirPathHostileDomainStaysInside: incluso con un dominio hostil, el
// directorio de backups derivado del slug debe quedar DENTRO de backupDir:
// el path traversal ("x/../../tmp/evil") no puede escapar del directorio
// raíz de snapshots.
func TestBackupDirPathHostileDomainStaysInside(t *testing.T) {
	backupDir := "/backups"
	hostile := []string{"x/../../tmp/evil", "../..", "..", "/etc/passwd", "a b"}

	for _, domainName := range hostile {
		got := files.BackupDirPath(backupDir, domainName)
		want := filepath.Join(backupDir, domain.DomainSlug(domainName))
		if got != want {
			t.Errorf("BackupDirPath(%q, %q) = %q; se esperaba %q", backupDir, domainName, got, want)
		}
		if !strings.HasPrefix(got, backupDir+string(filepath.Separator)) {
			t.Errorf("BackupDirPath(%q, %q) = %q: debe quedar dentro de backupDir", backupDir, domainName, got)
		}
	}
}
