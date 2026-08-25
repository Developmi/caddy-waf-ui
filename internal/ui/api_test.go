package ui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adminStubUI simula la Admin API de Caddy (:2019) para que la cadena de
// servicio complete la recarga en los tests de handlers REST (package ui).
type adminStubUI struct {
	reloads int
}

func (s *adminStubUI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the UI verifies the live
		// config via GET /config/apps/http/servers. The stub mirrors that
		// contract: it serves the fixture host (example.com).
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("el stub esperaba POST /load, recibió %s %s", r.Method, r.URL.Path)
		}
		s.reloads++
		w.WriteHeader(http.StatusOK)
	})
}

// setupUIEnv prepara el entorno de archivos/env para los handlers REST del
// paquete ui (misma convención D2 que los tests de integración) y devuelve el
// router montado. Sin auth: los handlers se ejercitan directamente.
func setupUIEnv(t *testing.T) *http.ServeMux {
	t.Helper()
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

	server := httptest.NewServer((&adminStubUI{}).handler(t))
	t.Cleanup(server.Close)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return NewRouter()
}

// seedUISnapshot siembra un snapshot en el dir de backups del slug.
func seedUISnapshot(t *testing.T, slug, name, content string) {
	t.Helper()
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), slug)
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("fallo creando dir de backups: %v", err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
		t.Fatalf("fallo sembrando snapshot %s: %v", name, err)
	}
}

func apiRequest(t *testing.T, method, path, body string) *http.Request {
	req, err := http.NewRequest(method, path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("fallo creando request: %v", err)
	}
	return req
}

// TestAPISetModeMalformedJSONReturns400: un cuerpo que no es JSON válido se
// rechaza con 400 (W2, rama decode de HandleSetMode).
func TestAPISetModeMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con payload malformado, se obtuvo %d", rec.Code)
	}
}

// TestAPISetModeOversizedBodyReturns413: un cuerpo que supera el límite de
// 1 MiB (MaxBytesReader) se rechaza con 413, no con un 400 genérico (hallazgo
// J1, defensa contra DoS por memoria).
func TestAPISetModeOversizedBodyReturns413(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"mode":"On","pad":"` + strings.Repeat("a", 1<<20) + `"}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", body))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("se esperaba 413 con body > 1MiB, se obtuvo %d", rec.Code)
	}
}

// TestAPISetModeInvalidModeReturns400: un modo inválido se traduce a 400
// (contrato REST ErrInvalidMode).
func TestAPISetModeInvalidModeReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"BlockAll"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con modo inválido, se obtuvo %d", rec.Code)
	}
}

// TestAPISetModeInvalidDomainReturns400: un dominio que no pasa la validación
// estricta se traduce a 400 vía service.ErrInvalidDomain (handoff F2, mismo
// patrón que ErrInvalidMode) - es un error de cliente, no de servidor.
func TestAPISetModeInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con dominio inválido, se obtuvo %d", rec.Code)
	}
}

// TestAPISetModeServiceErrorReturns500: un error del servicio que NO es de
// validación se traduce a 500 (W2, rama error genérico).
func TestAPISetModeServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	// managedDir apunta a un archivo: la lectura del estado previo falla ENOTDIR.
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("se esperaba 500 con error de servicio, se obtuvo %d", rec.Code)
	}
}

// TestAPISetModeSuccess: PUT válido regenera el overlay y responde el
// contrato de confirmación.
func TestAPISetModeSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/mode", `{"mode":"On"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Errorf("el cuerpo no confirma el éxito: %s", rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("no se generó el overlay: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("el overlay no contiene el modo enviado:\n%s", overlay)
	}
}

// TestAPISetExclusionsMalformedJSONReturns400: rama decode de
// HandleSetExclusions (W2).
func TestAPISetExclusionsMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con payload malformado, se obtuvo %d", rec.Code)
	}
}

// TestAPISetExclusionsValidationErrorReturns400: una exclusión que no pasa la
// validación es un payload de cliente inválido → 400, no un fallo de servidor
// (SUGGESTION #4 del verify: validación antes de la cadena, como HandleSetMode).
func TestAPISetExclusionsValidationErrorReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"exclusions":[{"type":"id","value":"941100","param":"q\nSecRuleEngine Off"}]}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con exclusión inválida, se obtuvo %d", rec.Code)
	}
}

// TestAPISetExclusionsUnknownTypeReturns400 (triangulación): un tipo de
// exclusión desconocido también se rechaza con 400 antes de tocar la cadena.
func TestAPISetExclusionsUnknownTypeReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[{"type":"bogus","value":"1"}]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con tipo de exclusión desconocido, se obtuvo %d", rec.Code)
	}
}

// TestAPISetExclusionsInvalidDomainReturns400: un dominio inválido es 400 vía
// service.ErrInvalidDomain (handoff F2) incluso con payload de exclusiones
// válido.
func TestAPISetExclusionsInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/exclusions", `{"exclusions":[{"type":"id","value":"941100"}]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con dominio inválido, se obtuvo %d", rec.Code)
	}
}

// TestAPISetExclusionsServiceErrorReturns500: con un payload VÁLIDO, un error
// real de la cadena (managedDir es un archivo → ENOTDIR al leer el estado
// previo) sigue devolviendo 500 - solo la validación de payload es 400.
func TestAPISetExclusionsServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", `{"exclusions":[{"type":"id","value":"941100"}]}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("se esperaba 500 con error de servicio, se obtuvo %d", rec.Code)
	}
}

// TestAPISetExclusionsSuccess: PUT válido de exclusiones → 200.
func TestAPISetExclusionsSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	body := `{"exclusions":[{"type":"id","value":"941100","param":"q"}]}`
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/exclusions", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "exclusions-example_com.conf"))
	if err != nil {
		t.Fatalf("no se generó el overlay de exclusiones: %v", err)
	}
	if !strings.Contains(string(overlay), "ARGS:q") {
		t.Errorf("el overlay no contiene la exclusión targeteada:\n%s", overlay)
	}
}

// TestAPISetIPRulesMalformedJSONReturns400: rama decode de HandleSetIPRules
// (W2).
func TestAPISetIPRulesMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con payload malformado, se obtuvo %d", rec.Code)
	}
}

// TestAPISetIPRulesValidationErrorReturns400: una entrada IP inválida es un
// payload de cliente inválido → 400, no un fallo de servidor (SUGGESTION #4).
func TestAPISetIPRulesValidationErrorReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["not-an-ip"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con entrada IP inválida, se obtuvo %d", rec.Code)
	}
}

// TestAPISetIPRulesAllowlistInvalidReturns400 (triangulación): la validación
// cubre también la allowlist, no solo la denylist.
func TestAPISetIPRulesAllowlistInvalidReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"allowlist":["300.300.300.300"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con entrada de allowlist inválida, se obtuvo %d", rec.Code)
	}
}

// TestAPISetIPRulesInvalidDomainReturns400: un dominio inválido es 400 vía
// service.ErrInvalidDomain (handoff F2) incluso con payload de IP válido.
func TestAPISetIPRulesInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/bad%20domain/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con dominio inválido, se obtuvo %d", rec.Code)
	}
}

// TestAPISetIPRulesServiceErrorReturns500: con un payload VÁLIDO, un error
// real de la cadena (managedDir es un archivo → ENOTDIR) sigue devolviendo
// 500 - solo la validación de payload es 400.
func TestAPISetIPRulesServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("se esperaba 500 con error de servicio, se obtuvo %d", rec.Code)
	}
}

// TestAPISetIPRulesSuccess: PUT válido de reglas IP → 200.
func TestAPISetIPRulesSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPut, "/api/sites/example.com/iprules", `{"denylist":["192.0.2.5"]}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ip-rules-example_com.conf"))
	if err != nil {
		t.Fatalf("no se generó el overlay de ip-rules: %v", err)
	}
	if !strings.Contains(string(overlay), "192.0.2.5/32") {
		t.Errorf("el overlay no contiene la IP normalizada:\n%s", overlay)
	}
}

// TestAPIListBackupsCorruptDirReturns500: un backup dir corrupto (archivo en
// vez de directorio) produce 500 - nunca un JSON inventado (W2).
func TestAPIListBackupsCorruptDirReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("se esperaba 500 con backup dir corrupto, se obtuvo %d", rec.Code)
	}
}

// TestAPIListBackupsEmptyReturns200: sin backups responde 200 con [] (estado
// vacío honesto).
func TestAPIListBackupsEmptyReturns200(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 sin backups, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("sin backups el cuerpo debe ser un array vacío: %s", rec.Body.String())
	}
}

// TestAPIListBackupsSuccess (triangulación): con snapshots el listado los
// incluye en el JSON.
func TestAPIListBackupsSuccess(t *testing.T) {
	handler := setupUIEnv(t)
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "waf-2020")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodGet, "/api/sites/example.com/backups", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2020-01-01T00-00-00Z") || !strings.Contains(rec.Body.String(), "waf") {
		t.Errorf("el listado debe incluir los snapshots: %s", rec.Body.String())
	}
}

// TestAPIRollbackMalformedJSONReturns400: rama decode de HandleRollback (W2).
func TestAPIRollbackMalformedJSONReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con payload malformado, se obtuvo %d", rec.Code)
	}
}

// TestAPIRollbackMissingBackupReturns400: un backup inexistente (pero con
// nombre canónico válido) se traduce a 400 vía ErrInvalidBackup (W2).
func TestAPIRollbackMissingBackupReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2099-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con backup inexistente, se obtuvo %d", rec.Code)
	}
}

// TestAPIRollbackInvalidDomainReturns400: un dominio inválido es 400 vía
// service.ErrInvalidDomain (handoff F2) antes de tocar la cadena.
func TestAPIRollbackInvalidDomainReturns400(t *testing.T) {
	handler := setupUIEnv(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/bad%20domain/rollback", `{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("se esperaba 400 con dominio inválido, se obtuvo %d", rec.Code)
	}
}

// TestAPIRollbackServiceErrorReturns500: un error de servicio distinto de
// ErrInvalidBackup se traduce a 500 (W2, rama error genérico).
func TestAPIRollbackServiceErrorReturns500(t *testing.T) {
	handler := setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2099-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("se esperaba 500 con error de servicio, se obtuvo %d", rec.Code)
	}
}

// TestAPIRollbackSuccess: rollback válido restaura el overlay y responde 200.
func TestAPIRollbackSuccess(t *testing.T) {
	handler := setupUIEnv(t)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "estado restaurado")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, apiRequest(t, http.MethodPost, "/api/sites/example.com/rollback", `{"backup":"2020-01-01T00-00-00Z.waf.conf"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d (%s)", rec.Code, rec.Body.String())
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("no se restauró el overlay: %v", err)
	}
	if string(overlay) != "estado restaurado" {
		t.Errorf("el overlay debe contener los bytes del snapshot: %q", overlay)
	}
}

// TestAPIHealthReturnsOK: HealthHandler responde 200 con el contrato de
// readiness. /health NO es ruta del mux de la API (main.go lo monta aparte,
// fuera del auth): el handler se ejercita directamente.
func TestAPIHealthReturnsOK(t *testing.T) {
	rec := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rec, apiRequest(t, http.MethodGet, "/health", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("el cuerpo de /health no es el esperado: %s", rec.Body.String())
	}
}
