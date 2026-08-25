package iprules

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// IPRules contiene las listas de direcciones IP o bloques CIDR.
type IPRules struct {
	Allowlist []string `json:"allowlist"`
	Denylist  []string `json:"denylist"`
}

// Plantilla basada en los ejemplos de configuración nativa de Caddy.
const ipRulesTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}

{{ if .DenyStr -}}
# Denylist
@ip_deny_{{ .Slug }} {
    remote_ip {{ .DenyStr }}
}
abort @ip_deny_{{ .Slug }}
{{ end }}
{{- if .AllowStr }}
# Allowlist (if set, all other IPs are denied)
@ip_allow_{{ .Slug }} {
    not remote_ip {{ .AllowStr }}
}
abort @ip_allow_{{ .Slug }}
{{ end }}
{{- if and (not .DenyStr) (not .AllowStr) -}}
# No IP rules configured for this domain.
{{ end }}
`

type ipRulesData struct {
	Slug     string
	Header   string
	DenyStr  string
	AllowStr string
}

// ipRulesTmpl se parsea UNA vez a nivel de paquete (hallazgo J5-8), mismo
// patrón que ui/embed.go: el template constante jamás falla al parsear.
var ipRulesTmpl = template.Must(template.New("iprules").Parse(ipRulesTemplate))

// normalizeIPEntry valida una entrada IP o CIDR y la normaliza a notación CIDR:
// una IP suelta queda como /32 (IPv4) o /128 (IPv6). Devuelve error ante
// cualquier valor no parseable, evitando que una entrada maliciosa escape el
// bloque de matchers de Caddy (ej: "1.2.3.4}\nabort @foo").
func normalizeIPEntry(entry string) (string, error) {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		return ipnet.String(), nil
	}

	if ip := net.ParseIP(entry); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}

	return "", fmt.Errorf("entrada IP inválida %q: se espera una IP o un bloque CIDR", entry)
}

// normalizeIPEntries valida y normaliza una lista completa de entradas.
func normalizeIPEntries(entries []string) ([]string, error) {
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		norm, err := normalizeIPEntry(entry)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, norm)
	}
	return normalized, nil
}

// ValidateIPRules valida ambas listas (allow y deny) sin generar configuración.
// La cadena de servicio (D2) la invoca ANTES del backup para fallar rápido y
// no dejar snapshots de entradas inválidas.
func ValidateIPRules(rules IPRules) error {
	if _, err := normalizeIPEntries(rules.Denylist); err != nil {
		return err
	}
	_, err := normalizeIPEntries(rules.Allowlist)
	return err
}

// GenerateSnippet crea el bloque de configuración de matchers de Caddy para bloqueo de IPs.
// Es una función pura y no interactúa con el disco[cite: 1].
func GenerateSnippet(site *domain.Site, rules IPRules) ([]byte, error) {
	denyList, err := normalizeIPEntries(rules.Denylist)
	if err != nil {
		return nil, err
	}

	allowList, err := normalizeIPEntries(rules.Allowlist)
	if err != nil {
		return nil, err
	}

	data := ipRulesData{
		Slug:   domain.DomainSlug(site.Domain),
		Header: domain.Header(site.Domain, "", time.Now()),
		// Unimos los slices en un solo string separado por espacios para el Caddyfile
		DenyStr:  strings.Join(denyList, " "),
		AllowStr: strings.Join(allowList, " "),
	}

	var buf bytes.Buffer
	if err := ipRulesTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("error ejecutando template de ip-rules: %w", err)
	}

	return buf.Bytes(), nil
}
