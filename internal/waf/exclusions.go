package waf

import (
	"bytes"
	"fmt"
	"regexp"
	"text/template"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// ExclusionType define los tipos de exclusiones soportadas por nuestra UI.
type ExclusionType string

const (
	ExcludeByID  ExclusionType = "id"
	ExcludeByTag ExclusionType = "tag"
)

// Exclusion representa una regla específica para desactivar en el CRS de Coraza.
// Param, cuando no está vacío, acota la exclusión al parámetro de query ARGS:<param>
// (decisión D5); si está vacío, la exclusión es de nivel URI (directiva suelta).
type Exclusion struct {
	Type  ExclusionType `json:"type"`
	Value string        `json:"value"`
	Param string        `json:"param,omitempty"`
}

// idBase es la base de los ids autogenerados para las reglas SecRule que
// aplican ctl:ruleRemoveById de forma targeteada por parámetro (D5: 9000001+).
const idBase = 9000001

const exclusionsTemplate = `# Caddy WAF UI managed - do not edit manually
{{ .Header }}

{{ range .Exclusions -}}
{{ if eq .Type "id" -}}
{{ if .Param -}}
SecRule ARGS:{{ .Param }} "@unconditionalMatch" "id:{{ .ID }},phase:2,pass,nolog,ctl:ruleRemoveById={{ .Value }}"
{{ else -}}
SecRuleRemoveById {{ .Value }}
{{ end -}}
{{ else if eq .Type "tag" -}}
{{ if .Param -}}
SecRule ARGS:{{ .Param }} "@unconditionalMatch" "id:{{ .ID }},phase:2,pass,nolog,ctl:ruleRemoveByTag={{ .Value }}"
{{ else -}}
SecRuleRemoveByTag "{{ .Value }}"
{{ end -}}
{{ end -}}
{{ else -}}
# No exclusions configured for this domain.
{{ end }}
`

// exclusionRow es la entrada ya validada y deduplicada lista para renderizar:
// lleva el id autogenerado (0 = nivel URI, sin SecRule propia).
type exclusionRow struct {
	Exclusion
	ID int
}

type exclusionsData struct {
	Header     string
	Exclusions []exclusionRow
}

// exclusionsTmpl se parsea UNA vez a nivel de paquete (hallazgo J5-8), mismo
// patrón que ui/embed.go: el template constante jamás falla al parsear.
var exclusionsTmpl = template.Must(template.New("exclusions").Parse(exclusionsTemplate))

// Patrones estrictos para los valores de exclusión: rechazan cualquier carácter
// de control, comillas, # o espacios que permitiría inyectar directivas CRS.
var (
	exclusionIDRegex  = regexp.MustCompile(`^[0-9]+$`)
	exclusionTagRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// Los nombres de parámetros de query se mantienen igual de estrictos
	// porque viajan literalmente dentro de ARGS:<param> en el Caddyfile.
	exclusionParamRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// validateExclusions valida cada entrada antes del renderizado para evitar
// inyección de directivas CRS (ej: "\nSecRuleEngine Off"). Ante cualquier
// entrada inválida devuelve un error explícito (fail-loud).
func validateExclusions(exclusions []Exclusion) error {
	for _, ex := range exclusions {
		switch ex.Type {
		case ExcludeByID:
			if !exclusionIDRegex.MatchString(ex.Value) {
				return fmt.Errorf("exclusión por id inválida %q: solo se admiten dígitos", ex.Value)
			}
		case ExcludeByTag:
			if !exclusionTagRegex.MatchString(ex.Value) {
				return fmt.Errorf("exclusión por tag inválida %q: solo se admiten letras, números, guiones y guiones bajos", ex.Value)
			}
		default:
			return fmt.Errorf("tipo de exclusión desconocido %q: solo se admiten %q o %q", ex.Type, ExcludeByID, ExcludeByTag)
		}
		if ex.Param != "" && !exclusionParamRegex.MatchString(ex.Param) {
			return fmt.Errorf("parámetro de exclusión inválido %q: solo se admiten letras, números, guiones y guiones bajos", ex.Param)
		}
	}
	return nil
}

// ValidateExclusions expone la validación al servicio compartido (D2) para que
// la cadena valide ANTES de tomar el backup (validate → backup → generate...).
func ValidateExclusions(exclusions []Exclusion) error {
	return validateExclusions(exclusions)
}

// dedupeExclusions elimina entradas repetidas (misma type+value+param).
// La primera aparición gana; las demás se descartan (escenario "duplicados
// deduplicados" del spec waf-exclusions).
func dedupeExclusions(exclusions []Exclusion) []Exclusion {
	seen := make(map[string]struct{}, len(exclusions))
	unique := make([]Exclusion, 0, len(exclusions))
	for _, ex := range exclusions {
		key := string(ex.Type) + "\x00" + ex.Value + "\x00" + ex.Param
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, ex)
	}
	return unique
}

// GenerateExclusions crea el bloque de configuración con las reglas CRS excluidas.
// Es una función pura, libre de efectos secundarios.
func GenerateExclusions(site *domain.Site, exclusions []Exclusion) ([]byte, error) {
	if err := validateExclusions(exclusions); err != nil {
		return nil, err
	}

	// Las exclusiones targeteadas por parámetro reciben ids propios 9000001+
	// en orden de aparición (D5), solo después de descartar duplicados.
	rows := make([]exclusionRow, 0, len(exclusions))
	nextID := idBase
	for _, ex := range dedupeExclusions(exclusions) {
		row := exclusionRow{Exclusion: ex}
		if ex.Param != "" {
			row.ID = nextID
			nextID++
		}
		rows = append(rows, row)
	}

	// Cabecera de 2 segmentos (sin modo): contrato compartido domain.Header.
	data := exclusionsData{
		Header:     domain.Header(site.Domain, "", time.Now()),
		Exclusions: rows,
	}

	var buf bytes.Buffer
	if err := exclusionsTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("error ejecutando template de exclusiones: %w", err)
	}

	return buf.Bytes(), nil
}
