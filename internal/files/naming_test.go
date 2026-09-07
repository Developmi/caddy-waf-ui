package files_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
)

// TestDomainSlug lives in internal/domain/slug_test.go (the function moved
// to the pure-domain boundary, finding J5-5); this file keeps the tests of
// the paths derived from the slug.

func TestBackupDirPath(t *testing.T) {
	tests := []struct {
		name      string
		backupDir string
		domain    string
		expected  string
	}{
		{"Normal domain", "/backups", "api.example.com", "/backups/api_example_com"},
		{"Wildcard domain", "/backups", "*.example.com", "/backups/wildcard_example_com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := files.BackupDirPath(tt.backupDir, tt.domain)
			if result != filepath.Clean(tt.expected) {
				t.Errorf("BackupDirPath(%q, %q) = %q; expected %q", tt.backupDir, tt.domain, result, tt.expected)
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
				t.Fatalf("OverlayPath(%q) failed: %v", tt.fileType, err)
			}
			if result != filepath.Clean(tt.expected) {
				t.Errorf("OverlayPath(%q) = %q; expected %q", tt.fileType, result, tt.expected)
			}
		})
	}

	// Unknown type → explicit error (fail-loud).
	if _, err := files.OverlayPath("/ui-managed", "caddyfile", "api.example.com"); err == nil {
		t.Error("OverlayPath with an unknown type must fail")
	}
}

// TestBackupDirPathHostileDomainStaysInside: even with a hostile domain, the
// backups directory derived from the slug must stay INSIDE backupDir:
// the path traversal ("x/../../tmp/evil") cannot escape the root snapshots
// directory.
func TestBackupDirPathHostileDomainStaysInside(t *testing.T) {
	backupDir := "/backups"
	hostile := []string{"x/../../tmp/evil", "../..", "..", "/etc/passwd", "a b"}

	for _, domainName := range hostile {
		got := files.BackupDirPath(backupDir, domainName)
		want := filepath.Join(backupDir, domain.DomainSlug(domainName))
		if got != want {
			t.Errorf("BackupDirPath(%q, %q) = %q; expected %q", backupDir, domainName, got, want)
		}
		if !strings.HasPrefix(got, backupDir+string(filepath.Separator)) {
			t.Errorf("BackupDirPath(%q, %q) = %q: must stay inside backupDir", backupDir, domainName, got)
		}
	}
}
