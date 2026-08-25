package waf

import (
	"bytes"
	"path/filepath"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Template exacto basado en las especificaciones de características.
// Utilizamos comillas invertidas concatenadas para que Go no rompa la sintaxis del string.
// El bloque coraza_waf es inline (importable directo en un site block), sin
// wrapper de snippet con nombre: la cabecera de 3 segmentos (# domain: | mode: |
// updated:) es el contrato que parsea el scanner (domain.Header/ParseHeader).
// El template se parsea UNA vez a nivel de paquete (hallazgo J5-8), mismo
// patrón que ui/embed.go: los constantes jamás fallan al parsear.
const wafTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}
coraza_waf {
    directives ` + "`" + `
        Include /etc/caddy/coraza.conf
        Include /etc/caddy/owasp-crs/crs-setup.conf
        Include /etc/caddy/owasp-crs/rules/*.conf
        SecRuleEngine {{ .Mode }}
        Include {{ .ExclusionsInclude }}
        SecAuditEngine RelevantOnly
        SecAuditLog {{ .AuditPath }}
        SecAuditLogFormat JSON
        SecAuditLogParts ABCDEFGHIJKZ
    ` + "`" + `
}
`

var wafTmpl = template.Must(template.New("waf").Parse(wafTemplate))

type templateData struct {
	Slug              string
	Mode              domain.WAFMode
	Header            string
	AuditPath         string
	ExclusionsInclude string
}

// GenerateSnippet crea el bloque de configuración de Caddy para el WAF de un dominio.
// Es una función pura que no interactúa con el disco ni con el entorno: el caller
// le pasa auditPath (normalmente config.AuditLogPath(), que honra CADDY_UI_AUDIT_LOG)
// para que la ruta del SecAuditLog del overlay coincida con la que consume el
// lector de auditoría (invariante M4), e includeDir (normalmente
// config.IncludeDir(), CADDY_UI_INCLUDE_DIR) para la directiva Include de
// exclusiones - la vista de CADDY del directorio de overlays, que NO es
// necesariamente CADDY_UI_MANAGED_DIR (hallazgo J5-1: la UI y Caddy montan el
// mismo volumen en puntos distintos de cada contenedor).
func GenerateSnippet(site *domain.Site, auditPath, includeDir string) ([]byte, error) {
	slug := domain.DomainSlug(site.Domain)

	data := templateData{
		Slug:              slug,
		Mode:              site.Mode,
		Header:            domain.Header(site.Domain, site.Mode, time.Now()),
		AuditPath:         auditPath,
		ExclusionsInclude: filepath.Join(includeDir, "exclusions-"+slug+".conf"),
	}

	var buf bytes.Buffer
	if err := wafTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
