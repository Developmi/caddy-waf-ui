package files

import (
	"fmt"
	"path/filepath"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Overlay types managed by the UI (finding J5-7): they are the on-disk
// naming contract - {prefix}-{slug}.conf for the overlays and
// {ISO8601}.{type}.conf for the backup snapshots. A single place avoids the
// loose "waf" | "exclusions" | "ip-rules" strings in regexes, switches and
// call sites.
const (
	FileTypeWAF        = "waf"
	FileTypeExclusions = "exclusions"
	FileTypeIPRules    = "ip-rules"
)

// WAFConfigPath returns the expected path for the WAF conf file of a domain[cite: 1].
func WAFConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/waf-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// ExclusionsConfigPath returns the expected path for the exclusions file[cite: 1].
func ExclusionsConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/exclusions-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// IPRulesConfigPath returns the expected path for the IP rules file[cite: 1].
func IPRulesConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/ip-rules-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// BackupDirPath returns the directory where the snapshots of a domain are
// stored. It uses the normalized slug so the "*" wildcard never appears raw
// in the path (bug #265).
func BackupDirPath(backupDir, domainName string) string {
	return filepath.Join(backupDir, domain.DomainSlug(domainName))
}

// OverlayPath returns the path of the overlay of the given type
// (FileTypeWAF | FileTypeExclusions | FileTypeIPRules); error if the type is
// unknown. It centralizes the type → conf file mapping shared by Backup and
// RestoreBackup.
func OverlayPath(managedDir, fileType, domainName string) (string, error) {
	switch fileType {
	case FileTypeWAF:
		return WAFConfigPath(managedDir, domainName), nil
	case FileTypeExclusions:
		return ExclusionsConfigPath(managedDir, domainName), nil
	case FileTypeIPRules:
		return IPRulesConfigPath(managedDir, domainName), nil
	default:
		return "", fmt.Errorf("unknown overlay type: %s", fileType)
	}
}
