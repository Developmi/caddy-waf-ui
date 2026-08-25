package integration_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

// adminStub simula la Admin API de Caddy (:2019) para que la cadena de
// servicio complete el paso de recarga sin tocar un Caddy real.
type adminStub struct {
	reloads int
}

func (s *adminStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the UI verifies the live
		// config via GET /config/apps/http/servers. The stub mirrors that
		// contract: it serves the fixture host (example.com).
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("el stub esperaba POST /load, recibió %s %s", r.Method, r.URL.Path)
		}
		s.reloads++
		w.WriteHeader(http.StatusOK)
	})
}

// setupEnv prepara el entorno completo: token, directorios temporales, un
// Caddyfile y el stub de la Admin API. Devuelve el mux protegido por Bearer.
func setupEnv(t *testing.T, admin *adminStub) http.Handler {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	tmp := t.TempDir()
	managedDir := filepath.Join(tmp, "ui-managed")
	backupDir := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("fallo creando managedDir: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatalf("fallo escribiendo Caddyfile: %v", err)
	}
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)

	server := httptest.NewServer(admin.handler(t))
	t.Cleanup(server.Close)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return auth.Middleware(ui.NewRouter())
}

func bearerRequest(t *testing.T, method, path string, body []byte) *http.Request {
	req, err := http.NewRequest(method, path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("fallo creando request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer super-secret-token")
	return req
}

func TestAPISetModeRequiresBearer(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	// El middleware Bearer rechaza antes de llegar al mux: 401 sin cabecera.
	req, _ := http.NewRequest(http.MethodPut, "/api/sites/test.com/mode", bytes.NewBufferString(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("se esperaba 401 sin Bearer, se obtuvo %d", recorder.Code)
	}
}

func TestAPISetModeSuccessRegeneratesOverlay(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/mode", []byte(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"success"`) {
		t.Errorf("el cuerpo no confirma el éxito: %s", recorder.Body.String())
	}

	// El overlay fue regenerado con el modo nuevo y el dominio real en la cabecera.
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("no se generó el overlay waf-example_com.conf: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("el overlay no contiene el modo enviado:\n%s", overlay)
	}
	if !strings.Contains(string(overlay), "# domain: example.com") {
		t.Errorf("el overlay no conserva el dominio en la cabecera:\n%s", overlay)
	}

	if admin.reloads != 1 {
		t.Errorf("se esperaba exactamente 1 recarga de Caddy, se hicieron %d", admin.reloads)
	}
}

// TestAPISetExclusionsInvalidPayloadReturns400: exclusiones que no pasan la
// validación son un payload de cliente inválido → 400 a través del stack
// completo (Bearer → router → handler), sin recargar Caddy (SUGGESTION #4).
func TestAPISetExclusionsInvalidPayloadReturns400(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", []byte(`{"exclusions":[{"type":"bogus","value":"1"}]}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con exclusión inválida, se obtuvo %d (%s)", recorder.Code, recorder.Body.String())
	}
	if admin.reloads != 0 {
		t.Errorf("no debe recargarse Caddy con payload inválido, se hicieron %d recargas", admin.reloads)
	}
}

// TestAPISetIPRulesInvalidPayloadReturns400: una entrada IP no-CIDR es un
// payload de cliente inválido → 400, no un fallo de servidor (SUGGESTION #4).
func TestAPISetIPRulesInvalidPayloadReturns400(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPut, "/api/sites/example.com/iprules", []byte(`{"denylist":["not-an-ip"]}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con entrada IP inválida, se obtuvo %d (%s)", recorder.Code, recorder.Body.String())
	}
	if admin.reloads != 0 {
		t.Errorf("no debe recargarse Caddy con payload inválido, se hicieron %d recargas", admin.reloads)
	}
}

func TestAPIFlatEndpointRemoved(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	// El contrato viejo (plano) ya no existe: cualquier verbo/forma → 404.
	req := bearerRequest(t, http.MethodPost, "/api/mode?domain=example.com", []byte(`{"mode":"On"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Errorf("el endpoint plano /api/mode debe devolver 404, se obtuvo %d", recorder.Code)
	}
}

func TestAPIHealth(t *testing.T) {
	// /health es público y se monta en main.go FUERA del mux autenticado
	// (F1: la ruta ya no vive en el router de la API): el handler se ejercita
	// directamente, sin Bearer - los healthchecks del contenedor no llevan
	// credenciales.
	rec := httptest.NewRecorder()
	ui.HealthHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("se esperaba 200 en /health, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("el cuerpo de /health no es el esperado: %s", rec.Body.String())
	}
}

// seedIntegrationSnapshot siembra un snapshot en el dir de backups del slug.
func seedIntegrationSnapshot(t *testing.T, domain, name, content string) {
	t.Helper()
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), domain)
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("fallo creando dir de backups: %v", err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("fallo sembrando snapshot %s: %v", name, err)
	}
}

// TestAPIGetBackupsListsSnapshots: GET /api/sites/{domain}/backups devuelve
// los snapshots del dominio como JSON (spec backup-recovery: backups listados).
func TestAPIGetBackupsListsSnapshots(t *testing.T) {
	handler := setupEnv(t, &adminStub{})
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.exclusions.conf", "exc-2020")

	req := bearerRequest(t, http.MethodGet, "/api/sites/example.com/backups", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "2020-01-01T00-00-00Z") || !strings.Contains(body, "waf") || !strings.Contains(body, "exclusions") {
		t.Errorf("el listado debe incluir los snapshots sembrados: %s", body)
	}
	if !strings.Contains(body, `"Size":8`) {
		t.Errorf("el listado debe incluir el tamaño real del archivo: %s", body)
	}
}

// TestAPIGetBackupsEmptyReturnsEmptyArray: sin backups el endpoint responde
// 200 con un array vacío (estado vacío honesto, nunca 500).
func TestAPIGetBackupsEmptyReturnsEmptyArray(t *testing.T) {
	handler := setupEnv(t, &adminStub{})

	req := bearerRequest(t, http.MethodGet, "/api/sites/example.com/backups", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("sin backups se esperaba 200, se obtuvo %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "[]") {
		t.Errorf("sin backups el cuerpo debe ser un array vacío: %s", recorder.Body.String())
	}
}

// TestAPIRollbackRestoresSnapshot: POST /api/sites/{domain}/rollback restaura
// los bytes del snapshot indicado sobre el overlay y recarga Caddy.
func TestAPIRollbackRestoresSnapshot(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	seedIntegrationSnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "estado restaurado")

	req := bearerRequest(t, http.MethodPost, "/api/sites/example.com/rollback", []byte(`{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"success"`) {
		t.Errorf("el cuerpo no confirma el éxito: %s", recorder.Body.String())
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("no se restauró el overlay: %v", err)
	}
	if string(overlay) != "estado restaurado" {
		t.Errorf("el overlay debe contener los bytes del snapshot: %q", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("se esperaba exactamente 1 recarga de Caddy, se hicieron %d", admin.reloads)
	}
}

// TestAPIRollbackInvalidBackupRejected: un nombre de snapshot inseguro se
// rechaza con 400 y sin recargar Caddy (fail-fast antes de mutar).
func TestAPIRollbackInvalidBackupRejected(t *testing.T) {
	admin := &adminStub{}
	handler := setupEnv(t, admin)

	req := bearerRequest(t, http.MethodPost, "/api/sites/example.com/rollback", []byte(`{"backup":"../../etc/passwd"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con snapshot inválido, se obtuvo %d", recorder.Code)
	}
	if admin.reloads != 0 {
		t.Errorf("no debe recargarse Caddy con snapshot inválido, se hicieron %d recargas", admin.reloads)
	}
}
