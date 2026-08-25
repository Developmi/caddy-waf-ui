package files

import (
	"fmt"
	"path/filepath"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Tipos de overlay gestionados por la UI (hallazgo J5-7): son el contrato de
// nombres en disco - {prefijo}-{slug}.conf para los overlays y
// {ISO8601}.{tipo}.conf para los snapshots de backup. Un solo lugar evita los
// strings sueltos "waf" | "exclusions" | "ip-rules" en regex, switches y call
// sites.
const (
	FileTypeWAF        = "waf"
	FileTypeExclusions = "exclusions"
	FileTypeIPRules    = "ip-rules"
)

// WAFConfigPath devuelve la ruta esperada para el archivo conf del WAF de un dominio[cite: 1].
func WAFConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/waf-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// ExclusionsConfigPath devuelve la ruta esperada para el archivo de exclusiones[cite: 1].
func ExclusionsConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/exclusions-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// IPRulesConfigPath devuelve la ruta esperada para el archivo de reglas de IP[cite: 1].
func IPRulesConfigPath(managedDir, domainName string) string {
	return fmt.Sprintf("%s/ip-rules-%s.conf", managedDir, domain.DomainSlug(domainName))
}

// BackupDirPath devuelve el directorio donde se guardan los snapshots de un dominio.
// Usa el slug normalizado para que el comodín "*" nunca aparezca crudo en la ruta (bug #265).
func BackupDirPath(backupDir, domainName string) string {
	return filepath.Join(backupDir, domain.DomainSlug(domainName))
}

// OverlayPath devuelve la ruta del overlay del tipo indicado
// (FileTypeWAF | FileTypeExclusions | FileTypeIPRules); error si el tipo es
// desconocido. Centraliza el mapeo tipo → archivo conf que comparten Backup y
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
		return "", fmt.Errorf("tipo de overlay desconocido: %s", fileType)
	}
}
