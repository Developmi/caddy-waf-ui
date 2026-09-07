package waf

import (
	"bytes"
	"path/filepath"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// Exact template based on the feature specifications.
// We use concatenated backticks so Go does not break the string syntax.
// The coraza_waf block is inline (directly importable in a site block),
// without a named snippet wrapper: the 3-segment header (# domain: | mode: |
// updated:) is the contract parsed by the scanner (domain.Header/ParseHeader).
// The template is parsed ONCE at package level (finding J5-8), same pattern
// as ui/embed.go: the constants never fail to parse.
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

// GenerateSnippet creates the Caddy configuration block for the WAF of a
// domain. It is a pure function that does not interact with the disk or the
// environment: the caller passes auditPath (normally config.AuditLogPath(),
// which honors CADDY_UI_AUDIT_LOG) so the SecAuditLog path of the overlay
// matches the one consumed by the audit reader (invariant M4), and includeDir
// (normally config.IncludeDir(), CADDY_UI_INCLUDE_DIR) for the exclusions
// Include directive - the CADDY view of the overlays directory, which is NOT
// necessarily CADDY_UI_MANAGED_DIR (finding J5-1: the UI and Caddy mount the
// same volume at different points of each container).
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
