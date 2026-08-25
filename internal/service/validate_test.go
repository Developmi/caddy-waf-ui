package service_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// adminSpy simula la Admin API de Caddy (:2019) y cuenta las llamadas
// recibidas. El read-back D3 (GET /config/apps/http/servers) no se cuenta
// como recarga. Con la validación de dominio activa, el spy jamás recibe
// tráfico: el fallo ocurre antes de llegar al reload.
type adminSpy struct {
	calls int
}

func (s *adminSpy) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
			return
		}
		s.calls++
		w.WriteHeader(http.StatusOK)
	})
}

// validateEnv agrupa el entorno de archivos/env para los tests adversariales
// de dominio. Nombres propios (prefijo validate) para no colisionar con los
// helpers de chain_test.go, que el fixer de estructura refactoriza.
type validateEnv struct {
	managedDir string
	backupDir  string
	admin      *adminSpy
}

// setupValidateEnv prepara directorios temporales y un stub de la Admin API;
// el servicio lee todo por entorno (convención D2).
func setupValidateEnv(t *testing.T) *validateEnv {
	t.Helper()
	tmp := t.TempDir()
	env := &validateEnv{
		managedDir: filepath.Join(tmp, "ui-managed"),
		backupDir:  filepath.Join(tmp, "backups"),
		admin:      &adminSpy{},
	}
	if err := os.MkdirAll(env.managedDir, 0750); err != nil {
		t.Fatalf("fallo creando managedDir: %v", err)
	}

	server := httptest.NewServer(env.admin.handler(t))
	t.Cleanup(server.Close)

	t.Setenv("CADDY_UI_MANAGED_DIR", env.managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", env.backupDir)
	t.Setenv("CADDY_ADMIN_URL", server.URL)
	return env
}

// assertNoMutation verifica que una entrada de la cadena con dominio inválido
// NO produjo efectos secundarios: ningún overlay escrito, ningún backup
// creado y ninguna recarga de Caddy (fail-fast antes de mutar estado).
func assertNoMutation(t *testing.T, env *validateEnv) {
	t.Helper()
	entries, err := os.ReadDir(env.managedDir)
	if err != nil {
		t.Fatalf("fallo leyendo managedDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("no debe escribirse ningún overlay con dominio inválido, se encontró: %v", entries)
	}
	if _, err := os.Stat(env.backupDir); !os.IsNotExist(err) {
		t.Errorf("no debe crearse el directorio de backups con dominio inválido")
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy con dominio inválido, se hicieron %d llamadas", env.admin.calls)
	}
}

// TestValidateDomainRejectsHostileInput: el validador debe rechazar todo
// dominio que no sea un hostname estricto [a-zA-Z0-9.-] - incluyendo los
// payloads de inyección de directivas Caddyfile y de path traversal
// reportados por el judge J2. El error siempre envuelve ErrInvalidDomain
// (patrón sentinel, mismo estilo que ErrInvalidMode) para que los handlers
// REST puedan traducirlo a 400.
func TestValidateDomainRejectsHostileInput(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Vacío", ""},
		// Inyección de directivas Caddyfile vía la cabecera "# domain:" del
		// overlay: un salto de línea + directiva abortaría el snippet y
		// permitiría inyectar "respond 200" a nivel de sitio.
		{"Inyección directivas Caddyfile", "foo%0Aabort | mode: On%0Arespond 200%0A# x"},
		// Path traversal de backups: con el slug viejo, ".." y "/" llegaban
		// vivos a filepath.Join(backupDir, slug) (files/backup.go) y a
		// os.ReadFile/WriteFile. Debe rechazarse ANTES de llegar a backup.
		{"Path traversal relativo", "x/../../tmp/evil"},
		{"Subida de directorio", "../.."},
		{"Doble punto", ".."},
		{"Whitespace", "a b"},
		{"Slash", "a/b"},
		{"Doble punto consecutivo", "a..b"},
		{"Punto inicial", ".example.com"},
		{"Punto final", "example.com."},
		{"Label con guion inicial", "-a.com"},
		{"Label con guion final", "a-.com"},
		{"Guion solo", "-"},
		{"Dos puntos", "a:80"},
		{"Arroba", "a@b"},
		{"Comillas", `a"b`},
		{"Llaves", "a{b}c"},
		{"Signo peso", "a$b"},
		{"Porcentaje", "a%b"},
		{"Comodín", "*.example.com"},
		{"Backslash", `a\b`},
		{"Underscore", "a_b.com"},
		{"Control char NUL", "a\x00b"},
		{"Control char tab", "a\tb"},
		{"Newline crudo", "a\nb"},
		{"Caracteres no ASCII", "café.com"},
		{"Longitud total excesiva", strings.Repeat("a.", 127) + "a"},
		{"Label excesivo", "a" + strings.Repeat("b", 63) + ".com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateDomain(tt.domain)
			if err == nil {
				t.Fatalf("ValidateDomain(%q) debería fallar", tt.domain)
			}
			if !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("ValidateDomain(%q) debe envolver ErrInvalidDomain, se obtuvo: %v", tt.domain, err)
			}
		})
	}
}

// TestValidateDomainAcceptsValidHostnames: los hostnames/FQDN válidos deben
// pasar la validación estricta (incluido localhost, labels de un carácter y
// punycode).
func TestValidateDomainAcceptsValidHostnames(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"FQDN típico", "api.example.com"},
		{"Localhost", "localhost"},
		{"Label corto", "a.io"},
		{"Label único", "a"},
		{"Subdominios", "sub.domain.example.com"},
		{"Guiones internos", "mi-sitio.com"},
		{"Punycode", "xn--bcher-kva.example"},
		{"Solo dígitos", "127.0.0.1"},
		{"Longitud máxima", strings.Repeat("a.", 126) + "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := service.ValidateDomain(tt.domain); err != nil {
				t.Errorf("ValidateDomain(%q) no debería fallar: %v", tt.domain, err)
			}
		})
	}
}

// TestChainEntriesRejectHostileDomain: las 4 entradas públicas de la cadena
// (UpdateWAFMode, UpdateExclusions, UpdateIPRules, Rollback) deben rechazar
// los payloads hostiles del judge con ErrInvalidDomain ANTES de escribir
// archivos, crear backups o recargar Caddy. "x/../../tmp/evil" en particular
// se rechaza antes de llegar a la ruta de backups.
func TestChainEntriesRejectHostileDomain(t *testing.T) {
	hostile := []string{
		"foo%0Aabort | mode: On%0Arespond 200%0A# x",
		"x/../../tmp/evil",
		"../..",
		"a b",
		"a/b",
		"a..b",
	}

	for _, d := range hostile {
		t.Run(d, func(t *testing.T) {
			env := setupValidateEnv(t)

			if err := service.UpdateWAFMode(d, domain.ModeOn, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateWAFMode(%q) debe fallar con ErrInvalidDomain, se obtuvo: %v", d, err)
			}
			if err := service.UpdateExclusions(d, []waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateExclusions(%q) debe fallar con ErrInvalidDomain, se obtuvo: %v", d, err)
			}
			if err := service.UpdateIPRules(d, iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("UpdateIPRules(%q) debe fallar con ErrInvalidDomain, se obtuvo: %v", d, err)
			}
			if err := service.Rollback(d, "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1"); err == nil || !errors.Is(err, service.ErrInvalidDomain) {
				t.Errorf("Rollback(%q) debe fallar con ErrInvalidDomain, se obtuvo: %v", d, err)
			}

			assertNoMutation(t, env)
		})
	}
}

// TestRollbackInvalidDomainFailsBeforeMutation: un rollback con dominio
// inválido (aunque el snapshot sea válido) aborta en la validación de
// dominio: el overlay queda intacto, no se crean snapshots nuevos y Caddy no
// se recarga.
func TestRollbackInvalidDomainFailsBeforeMutation(t *testing.T) {
	env := setupValidateEnv(t)

	slug := domain.DomainSlug("api.example.com")
	overlay := filepath.Join(env.managedDir, "waf-"+slug+".conf")
	if err := os.WriteFile(overlay, []byte("previo"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	backupDir := filepath.Join(env.backupDir, slug)
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		t.Fatalf("fallo creando dir de backups: %v", err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "2020-01-01T00-00-00Z.waf.conf"), []byte("snapshot"), 0640); err != nil {
		t.Fatalf("fallo sembrando snapshot: %v", err)
	}

	err := service.Rollback("../..", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !errors.Is(err, service.ErrInvalidDomain) {
		t.Fatalf("se esperaba ErrInvalidDomain, se obtuvo: %v", err)
	}

	content, readErr := os.ReadFile(overlay)
	if readErr != nil || string(content) != "previo" {
		t.Errorf("el overlay no debe mutar con dominio inválido (contenido: %q, err: %v)", content, readErr)
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("fallo leyendo dir de backups: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("no deben crearse snapshots con dominio inválido, se encontraron %d", len(entries))
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy con dominio inválido, se hicieron %d llamadas", env.admin.calls)
	}
}
