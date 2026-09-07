package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// auditDirectives son las directivas de auditoría que el overlay inline debe
// conservar (S2): se verifican presentes y en orden dentro del bloque.
// defaultAuditPath es el valor por defecto de CADDY_UI_AUDIT_LOG - los tests
// pasan la ruta explícitamente (firma pura GenerateSnippet(site, auditPath,
// includeDir), invariante M4: el overlay y el lector sharen la misma ruta).
// defaultIncludeDir es el valor por defecto de CADDY_UI_INCLUDE_DIR (la vista
// de Caddy del directorio de overlays, hallazgo J5-1).
const (
	defaultAuditPath  = "/data/logs/coraza-audit.log"
	defaultIncludeDir = "/etc/caddy/ui-managed"
)

var auditDirectives = []string{
	"SecAuditEngine RelevantOnly",
	"SecAuditLog " + defaultAuditPath,
	"SecAuditLogFormat JSON",
	"SecAuditLogParts ABCDEFGHIJKZ",
}

// assertInlineOverlay verifica el contrato R1 del overlay inline (S1, S2):
// bloque coraza_waf top-level sin wrapper de snippet, header de 3 segmentos
// conservado (contrato del scanner), Include de exclusiones dentro del bloque
// y directivas de auditoría conservadas y en orden.
func assertInlineOverlay(t *testing.T, result, headerPrefix, slug, mode string) {
	t.Helper()

	// S1: el bloque coraza_waf debe estar a nivel raíz (columna 0), sin anidarse
	// en un snippet con nombre.
	topLevel := false
	for _, line := range strings.Split(result, "\n") {
		if line == "coraza_waf {" {
			topLevel = true
			break
		}
	}
	if !topLevel {
		t.Errorf("el overlay no contiene un bloque coraza_waf top-level (línea exacta \"coraza_waf {\"):\n%s", result)
	}

	// S1: prohibido el wrapper de snippet (waf_{slug}) {.
	if strings.Contains(result, "(waf_"+slug+") {") {
		t.Errorf("el overlay no debe declarar el snippet (waf_%s) {:\n%s", slug, result)
	}

	// Orden estructural completo: header → coraza_waf → SecRuleEngine → Include
	// de exclusiones → directivas de auditoría → cierre del bloque.
	order := []string{
		headerPrefix,
		"coraza_waf {",
		"SecRuleEngine " + mode,
		"Include /etc/caddy/ui-managed/exclusions-" + slug + ".conf",
	}
	order = append(order, auditDirectives...)

	prev := -1
	prevFragment := "<inicio>"
	for _, fragment := range order {
		idx := strings.Index(result, fragment)
		if idx < 0 {
			t.Errorf("el overlay inline no contiene el fragmento esperado: %q\nOverlay:\n%s", fragment, result)
			continue
		}
		if idx < prev {
			t.Errorf("fragmento %q fuera de orden (aparece antes que %q)", fragment, prevFragment)
		}
		prev = idx
		prevFragment = fragment
	}

	// S2: el bloque se cierra después de las directivas de auditoría.
	if closeIdx := strings.LastIndex(result, "}"); closeIdx < prev {
		t.Errorf("el bloque coraza_waf debe cerrarse después de las directivas de auditoría:\n%s", result)
	}
}

func TestGenerateSnippetInline(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	resultBytes, err := waf.GenerateSnippet(site, defaultAuditPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet falló inesperadamente: %v", err)
	}

	result := string(resultBytes)

	// S1 + S2: header de 3 segmentos conservado (contrato del scanner).
	assertInlineOverlay(t, result,
		"# domain: api.developmi.com | mode: DetectionOnly | updated: ",
		"api_developmi_com", "DetectionOnly")
}

// TestGenerateSnippetHonorsAuditPath verifica la invariante M4: la ruta del
// SecAuditLog en el overlay es la que el caller pasa (logs.AuditLogPath(), que
// honra CADDY_UI_AUDIT_LOG), no un valor hardcodeado.
func TestGenerateSnippetHonorsAuditPath(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	customPath := "/var/log/waf/custom-audit.log"
	resultBytes, err := waf.GenerateSnippet(site, customPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet falló inesperadamente: %v", err)
	}

	result := string(resultBytes)
	if !strings.Contains(result, "SecAuditLog "+customPath) {
		t.Errorf("el overlay debe contener SecAuditLog %q (invariante M4, CADDY_UI_AUDIT_LOG):\n%s", customPath, result)
	}
	if strings.Contains(result, "SecAuditLog /data/logs/coraza-audit.log") {
		t.Errorf("el overlay no debe contener la ruta hardcodeada cuando el caller pasa otra:\n%s", result)
	}
}

// TestGenerateSnippetHonorsIncludeDir verifica el hallazgo J5-1: la directiva
// Include de exclusiones del overlay debe referenciar el directorio de
// inclusión que el caller pasa (config.IncludeDir(), CADDY_UI_INCLUDE_DIR) -
// la vista de CADDY del volumen, NO un valor hardcodeado. Un despliegue con
// dirs personalizados deja de romperse silenciosamente.
func TestGenerateSnippetHonorsIncludeDir(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	customInclude := "/etc/caddy/custom-managed"
	resultBytes, err := waf.GenerateSnippet(site, defaultAuditPath, customInclude)
	if err != nil {
		t.Fatalf("GenerateSnippet falló inesperadamente: %v", err)
	}

	result := string(resultBytes)
	if !strings.Contains(result, "Include "+customInclude+"/exclusions-api_developmi_com.conf") {
		t.Errorf("el overlay debe incluir las exclusiones desde CADDY_UI_INCLUDE_DIR (%s):\n%s", customInclude, result)
	}
	if strings.Contains(result, "Include /etc/caddy/ui-managed/exclusions-api_developmi_com.conf") {
		t.Errorf("el overlay no debe contener la ruta hardcodeada cuando el caller pasa otra:\n%s", result)
	}
}

func TestGenerateSnippetInlineOnMode(t *testing.T) {
	site := &domain.Site{
		Domain: "app.example.org",
		Mode:   domain.ModeOn,
	}

	resultBytes, err := waf.GenerateSnippet(site, defaultAuditPath, defaultIncludeDir)
	if err != nil {
		t.Fatalf("GenerateSnippet falló inesperadamente: %v", err)
	}

	result := string(resultBytes)

	// Triangulación: otro dominio y modo On - el template debe renderizar los
	// valores reales del sitio, no una salida fija.
	assertInlineOverlay(t, result,
		"# domain: app.example.org | mode: On | updated: ",
		"app_example_org", "On")
}
