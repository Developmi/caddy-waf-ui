package domain_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// findSite busca un sitio por su slug normalizado iterando el slice devuelto
// por Scan (el Registry en memoria fue eliminado, hallazgo J5-6).
func findSite(sites []*domain.Site, slug string) (*domain.Site, bool) {
	for _, site := range sites {
		if domain.DomainSlug(site.Domain) == slug {
			return site, true
		}
	}
	return nil, false
}

// TestScanRegistersSitesFromHeaders verifica que el scanner parsea la cabecera
// "# domain: | mode: | updated:" de los overlays waf-*.conf y devuelve el dominio REAL
// (no el slug derivado del nombre de archivo).
func TestScanRegistersSitesFromHeaders(t *testing.T) {
	scanner := domain.NewScanner(filepath.Join("testdata"))

	sites, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan falló: %v", err)
	}

	// Dominio real con modo y timestamp de la cabecera.
	site, ok := findSite(sites, "api_example_com")
	if !ok {
		t.Fatal("No se registró api_example_com con la clave slug")
	}
	if site.Domain != "api.example.com" {
		t.Errorf("Domain = %q; se esperaba el dominio real %q (no el slug)", site.Domain, "api.example.com")
	}
	if site.Mode != domain.ModeOn {
		t.Errorf("Mode = %q; se esperaba %q", site.Mode, domain.ModeOn)
	}
	wantUpdated := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	if !site.Updated.Equal(wantUpdated) {
		t.Errorf("Updated = %v; se esperaba %v", site.Updated, wantUpdated)
	}

	// Comodín: el identificador es el slug normalizado (wildcard_example_com)
	// pero Site.Domain conserva el dominio real tal como viene en la cabecera.
	wsite, ok := findSite(sites, "wildcard_example_com")
	if !ok {
		t.Fatal("No se registró wildcard_example_com como identificador del dominio con comodín")
	}
	if wsite.Domain != "*.EXAMPLE.com" {
		t.Errorf("Domain = %q; se esperaba el dominio real %q", wsite.Domain, "*.EXAMPLE.com")
	}
	if wsite.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; se esperaba %q", wsite.Mode, domain.ModeDetectionOnly)
	}
	wantWildcardUpdated := time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC)
	if !wsite.Updated.Equal(wantWildcardUpdated) {
		t.Errorf("Updated = %v; se esperaba %v", wsite.Updated, wantWildcardUpdated)
	}

	// Archivo sin cabecera: omitido (no registrado) y el scan continuó con los demás.
	if _, ok := findSite(sites, "sin_cabecera"); ok {
		t.Error("El archivo sin cabecera no debió registrarse")
	}

	// Archivo que no es waf-*.conf: ignorado aunque tenga cabecera valida.
	if _, ok := findSite(sites, "exclusions_example_com"); ok {
		t.Error("El archivo exclusions-*.conf no debió registrarse")
	}

	if got := len(sites); got != 2 {
		t.Errorf("Se esperaban 2 sitios registrados, se encontraron %d", got)
	}
}

// seedOverlayDir prepara un directorio temporal con un único overlay waf-*.conf
// cuyo contenido es la cabecera dada, para tests de scanner aislados.
func seedOverlayDir(t *testing.T, header string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "waf-degraded_example_com.conf"), []byte(header), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	return dir
}

// TestScanRegistersDegradedSiteOnInvalidMode: un modo desconocido en la
// cabecera NO debe presentarse como un modo real (W1): el sitio se registra
// con DetectionOnly (default no-bloqueante, forward-compat) y el flag Degraded
// queda en true para que la UI advierta que el estado real en Caddy difiere.
func TestScanRegistersDegradedSiteOnInvalidMode(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | mode: BlockAll | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan falló: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("el sitio con modo inválido debe registrarse igualmente (no ocultarse)")
	}
	if site.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; se esperaba el default %q", site.Mode, domain.ModeDetectionOnly)
	}
	if !site.Degraded {
		t.Error("Degraded debe ser true cuando la cabecera trae un modo desconocido")
	}
}

// TestScanValidModeNotDegraded (triangulación): un modo válido nunca marca el
// sitio como degradado.
func TestScanValidModeNotDegraded(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | mode: On | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan falló: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("el sitio no se registró")
	}
	if site.Mode != domain.ModeOn {
		t.Errorf("Mode = %q; se esperaba %q", site.Mode, domain.ModeOn)
	}
	if site.Degraded {
		t.Error("un modo válido no debe marcar el sitio como degradado")
	}
}

// TestScanHeaderWithoutModeNotDegraded (triangulación): la ausencia de modo en
// la cabecera usa el default DetectionOnly sin marcar degradado - solo un modo
// PRESENTE pero desconocido es una señal de desincronización.
func TestScanHeaderWithoutModeNotDegraded(t *testing.T) {
	dir := seedOverlayDir(t, "# domain: degraded.example.com | updated: 2026-08-07T00:00:00Z\n")

	sites, err := domain.NewScanner(dir).Scan()
	if err != nil {
		t.Fatalf("Scan falló: %v", err)
	}

	site, ok := findSite(sites, "degraded_example_com")
	if !ok {
		t.Fatal("el sitio no se registró")
	}
	if site.Mode != domain.ModeDetectionOnly {
		t.Errorf("Mode = %q; se esperaba el default %q", site.Mode, domain.ModeDetectionOnly)
	}
	if site.Degraded {
		t.Error("un header sin modo no debe marcar el sitio como degradado")
	}
}

// TestScanMissingDirReturnsEmpty: un directorio inexistente no es un error:
// el scan devuelve lista vacía (estado vacío honesto, primer arranque).
func TestScanMissingDirReturnsEmpty(t *testing.T) {
	sites, err := domain.NewScanner(filepath.Join(t.TempDir(), "no-existe")).Scan()
	if err != nil {
		t.Fatalf("Scan con directorio inexistente no debe fallar: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("sin directorio se esperaba lista vacía, se encontraron %d sitios", len(sites))
	}
}
