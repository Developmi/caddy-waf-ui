package service_test

import (
	"bytes"
	"log/slog"
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

// adminStub simula la Admin API de Caddy (:2019) y registra cuántas veces se
// invocó POST /load. Con fail=true responde 500 para ejercitar la rama D6.
// onFail (opcional) se ejecuta ANTES de responder 500: permite que el test
// deteriore el entorno (ej: crear un directorio donde la restauración D6
// intentará escribir) para ejercitar el fallo de la propia restauración.
type adminStub struct {
	calls  int
	fail   bool
	onFail func()
}

func (s *adminStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read-back (D3): after every POST /load the service verifies the
		// live config via GET /config/apps/http/servers. The stub serves the
		// fixture host (example.com). NOT counted as a reload.
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`))
			return
		}
		s.calls++
		if r.Method != http.MethodPost || r.URL.Path != "/load" {
			t.Errorf("el stub esperaba POST /load, recibió %s %s", r.Method, r.URL.Path)
		}
		if s.fail {
			if s.onFail != nil {
				s.onFail()
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// chainEnv agrupa el entorno de archivos/env para un test de cadena.
type chainEnv struct {
	managedDir string
	backupDir  string
	admin      *adminStub
}

// setupChainEnv prepara directorios temporales, un Caddyfile de prueba y un
// stub de la Admin API; el servicio lee todo por entorno (convención D2).
func setupChainEnv(t *testing.T, failReload bool) *chainEnv {
	tmp := t.TempDir()
	managedDir := filepath.Join(tmp, "ui-managed")
	backupDir := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(managedDir, 0750); err != nil {
		t.Fatalf("fallo creando managedDir: %v", err)
	}

	caddyfile := filepath.Join(tmp, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte("example.com {\n}\n"), 0600); err != nil {
		t.Fatalf("fallo escribiendo Caddyfile: %v", err)
	}

	stub := &adminStub{fail: failReload}
	server := httptest.NewServer(stub.handler(t))
	t.Cleanup(server.Close)

	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfile)
	t.Setenv("CADDY_ADMIN_URL", server.URL)

	return &chainEnv{managedDir: managedDir, backupDir: backupDir, admin: stub}
}

// seedWAFOverlay crea un overlay waf-{slug}.conf con el contenido previo dado.
func seedWAFOverlay(t *testing.T, managedDir, domain, content string) {
	if err := os.WriteFile(
		filepath.Join(managedDir, "waf-"+strings.ReplaceAll(strings.ReplaceAll(domain, ".", "_"), "*", "wildcard")+".conf"),
		[]byte(content), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
}

const oldWAFContent = `# Caddy WAF UI managed - do not edit manually
# domain: api.example.com | mode: DetectionOnly | updated: 2026-01-01T00:00:00Z
(waf_api_example_com) {
    coraza_waf {
        directives ` + "`" + `
            SecRuleEngine DetectionOnly
        ` + "`" + `
    }
}
`

// captureLogs redirige slog a un buffer para poder asertar los eventos de
// auditoría (NIST AU-12) emitidos por la cadena. Restaura el handler previo.
func captureLogs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// snapshotCount cuenta los snapshots de un tipo en el dir de backups del slug.
func snapshotCount(t *testing.T, backupDir, slug, fileType string) int {
	dir := filepath.Join(backupDir, slug)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("fallo leyendo dir de backups: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), "."+fileType+".conf") {
			count++
		}
	}
	return count
}

// seedBackupSnapshot siembra un snapshot con el contenido dado en el dir del
// slug (simula un historial previo de backups).
func seedBackupSnapshot(t *testing.T, backupDir, slug, name, content string) {
	t.Helper()
	dir := filepath.Join(backupDir, slug)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatalf("fallo creando dir de backups: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0640); err != nil {
		t.Fatalf("fallo sembrando snapshot %s: %v", name, err)
	}
}

// newestSnapshot lee el snapshot más reciente de un tipo (el creado por el
// último backup) y devuelve su contenido.
func newestSnapshot(t *testing.T, backupDir, slug, fileType string) string {
	t.Helper()
	dir := filepath.Join(backupDir, slug)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("fallo leyendo dir de snapshots: %v", err)
	}
	newest := ""
	for _, e := range entries {
		if strings.Contains(e.Name(), "."+fileType+".conf") && e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		t.Fatalf("no hay snapshots de tipo %s en %s", fileType, dir)
	}
	content, err := os.ReadFile(filepath.Join(dir, newest))
	if err != nil {
		t.Fatalf("fallo leyendo snapshot %s: %v", newest, err)
	}
	return string(content)
}

func TestUpdateWAFModeChainSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	audit := captureLogs(t)

	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1"); err != nil {
		t.Fatalf("UpdateWAFMode falló: %v", err)
	}

	// Overlay regenerado con el modo nuevo y el dominio real en la cabecera.
	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("fallo leyendo overlay: %v", err)
	}
	if !strings.Contains(string(conf), "SecRuleEngine On") {
		t.Errorf("el overlay no contiene el modo nuevo:\n%s", conf)
	}
	if !strings.Contains(string(conf), "# domain: api.example.com") {
		t.Errorf("el overlay no conserva el dominio real en la cabecera:\n%s", conf)
	}

	// El snapshot debe contener el estado PREVIO: el backup ocurrió antes de escribir.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 1 {
		t.Fatalf("se esperaba 1 snapshot waf, se encontraron %d", got)
	}
	entries, err := os.ReadDir(filepath.Join(env.backupDir, "api_example_com"))
	if err != nil {
		t.Fatalf("fallo leyendo dir de snapshots: %v", err)
	}
	snapBytes, err := os.ReadFile(filepath.Join(env.backupDir, "api_example_com", entries[0].Name()))
	if err != nil {
		t.Fatalf("fallo leyendo snapshot: %v", err)
	}
	if string(snapBytes) != oldWAFContent {
		t.Errorf("el snapshot no contiene el estado previo (backup antes de escribir)")
	}

	if env.admin.calls != 1 {
		t.Errorf("se esperaba exactamente 1 recarga de Caddy, se hicieron %d", env.admin.calls)
	}

	if !strings.Contains(audit.String(), "waf_mode_changed") {
		t.Errorf("no se auditó waf_mode_changed:\n%s", audit.String())
	}
}

func TestUpdateWAFModeReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true) // stub responde 500
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateWAFMode debería fallar cuando la recarga falla")
	}

	// D6: no debe quedar overlay parcial - el contenido previo fue restaurado.
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("el overlay debería seguir existiendo tras restaurar: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("tras el fallo de recarga el overlay debe volver al estado previo (D6):\n%s", conf)
	}
}

func TestUpdateWAFModeReloadFailureRemovesNewFile(t *testing.T) {
	env := setupChainEnv(t, true) // sin overlay previo
	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateWAFMode debería fallar cuando la recarga falla")
	}

	// D6: si no existía archivo previo, el overlay nuevo debe eliminarse.
	if _, statErr := os.Stat(filepath.Join(env.managedDir, "waf-api_example_com.conf")); !os.IsNotExist(statErr) {
		t.Errorf("sin archivo previo, el overlay nuevo debe eliminarse tras el fallo de recarga (D6)")
	}
}

func TestUpdateWAFModeInvalidModeFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.WAFMode("BlockAll"), "192.0.2.1")
	if err == nil {
		t.Fatal("un modo inválido debería fallar la validación")
	}

	// La validación ocurre ANTES del backup: nada debe haberse escrito ni recargado.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no deberían crearse snapshots con entrada inválida, se encontraron %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debería recargarse Caddy con entrada inválida, se hicieron %d llamadas", env.admin.calls)
	}
	if strings.Contains(audit.String(), "waf_mode_changed") {
		t.Errorf("no debería auditarse un cambio exitoso con entrada inválida:\n%s", audit.String())
	}
}

func TestUpdateExclusionsSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100", Param: "q"}}, "192.0.2.1")
	if err != nil {
		t.Fatalf("UpdateExclusions falló: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("no se escribió el overlay de exclusiones: %v", readErr)
	}
	if !strings.Contains(string(conf), "ARGS:q") || !strings.Contains(string(conf), "9000001") {
		t.Errorf("el overlay no contiene la exclusión targeteada:\n%s", conf)
	}
	if env.admin.calls != 1 {
		t.Errorf("se esperaba 1 recarga, se hicieron %d", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_updated") {
		t.Errorf("no se auditó exclusions_updated:\n%s", audit.String())
	}
}

func TestUpdateExclusionsInvalidParamFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100", Param: "q\nSecRuleEngine Off"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("un parámetro inválido debería fallar la validación")
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "exclusions"); got != 0 {
		t.Errorf("no deberían crearse snapshots con entrada inválida, se encontraron %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debería recargarse Caddy con entrada inválida, se hicieron %d llamadas", env.admin.calls)
	}
}

func TestUpdateIPRulesSuccess(t *testing.T) {
	env := setupChainEnv(t, false)
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err != nil {
		t.Fatalf("UpdateIPRules falló: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("no se escribió el overlay de ip-rules: %v", readErr)
	}
	if !strings.Contains(string(conf), "192.0.2.5/32") {
		t.Errorf("el overlay no contiene la IP normalizada:\n%s", conf)
	}
	if env.admin.calls != 1 {
		t.Errorf("se esperaba 1 recarga, se hicieron %d", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_updated") {
		t.Errorf("no se auditó iprules_updated:\n%s", audit.String())
	}
}

func TestUpdateIPRulesInvalidEntryFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"not-an-ip"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("una entrada IP inválida debería fallar la validación")
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "ip-rules"); got != 0 {
		t.Errorf("no deberían crearse snapshots con entrada inválida, se encontraron %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debería recargarse Caddy con entrada inválida, se hicieron %d llamadas", env.admin.calls)
	}
}

const restoredWAFContent = `# Caddy WAF UI managed - do not edit manually
# domain: api.example.com | mode: Off | updated: 2020-01-01T00:00:00Z
(restored snippet)
`

// TestRollbackRestoresSnapshotAndBacksUpCurrent: Rollback restaura los bytes
// del snapshot elegido sobre el overlay, respalda PRIMERO el estado actual
// (snapshot más reciente), recarga Caddy y audita el evento.
func TestRollbackRestoresSnapshotAndBacksUpCurrent(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	audit := captureLogs(t)

	if err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1"); err != nil {
		t.Fatalf("Rollback falló: %v", err)
	}

	// El overlay debe contener exactamente los bytes del snapshot restaurado.
	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("fallo leyendo overlay: %v", err)
	}
	if string(conf) != restoredWAFContent {
		t.Errorf("el overlay debe contener los bytes del snapshot restaurado:\n%s", conf)
	}

	// El estado actual fue respaldado primero: 2 snapshots, el más nuevo = estado previo.
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 2 {
		t.Fatalf("se esperaban 2 snapshots waf (previo + restaurado), se encontraron %d", got)
	}
	if got := newestSnapshot(t, env.backupDir, "api_example_com", "waf"); got != oldWAFContent {
		t.Errorf("el snapshot más reciente debe contener el estado previo al rollback:\n%s", got)
	}

	if env.admin.calls != 1 {
		t.Errorf("se esperaba exactamente 1 recarga de Caddy, se hicieron %d", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_restored") {
		t.Errorf("no se auditó rollback_restored:\n%s", audit.String())
	}
}

// TestRollbackReloadFailureRestoresPreviousState: si la recarga falla, el
// overlay debe volver al estado previo al rollback (D6) y el evento auditado.
func TestRollbackReloadFailureRestoresPreviousState(t *testing.T) {
	env := setupChainEnv(t, true) // stub responde 500
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil {
		t.Fatal("Rollback debería fallar cuando la recarga falla")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("el overlay debería seguir existiendo tras la reversión: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("tras el fallo de recarga el overlay debe volver al estado previo (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "rollback_changed_but_reload_failed") {
		t.Errorf("no se auditó rollback_changed_but_reload_failed:\n%s", audit.String())
	}
}

// TestRollbackInvalidNameFailsBeforeMutation: un nombre de snapshot inseguro
// (path traversal) debe fallar la validación ANTES de respaldar, escribir o
// recargar (patrón validate-before-mutate de la cadena).
func TestRollbackInvalidNameFailsBeforeMutation(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "../../etc/passwd", "192.0.2.1")
	if err == nil {
		t.Fatal("un nombre de snapshot inseguro debería fallar la validación")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("el overlay no debe mutar con un snapshot inválido:\n%s", conf)
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no deberían crearse snapshots con nombre inválido, se encontraron %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debería recargarse Caddy con snapshot inválido, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") {
		t.Errorf("no se auditó rollback_failed:\n%s", audit.String())
	}
}

// TestRollbackMissingSnapshotFailsWithoutReload: un snapshot inexistente (raza
// entre listado y restauración) falla sin mutar el overlay ni recargar Caddy.
func TestRollbackMissingSnapshotFailsWithoutReload(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)

	err := service.Rollback("api.example.com", "2099-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil {
		t.Fatal("Rollback de un snapshot inexistente debería fallar")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("el overlay no debe mutar si el snapshot no existe:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debería recargarse Caddy si el snapshot no existe, se hicieron %d llamadas", env.admin.calls)
	}
}

// breakBackupDir apunta CADDY_UI_BACKUP_DIR a un ARCHIVO: todo MkdirAll bajo
// esa ruta falla con ENOTDIR, forzando el fallo del paso de backup de la
// cadena sin depender de permisos (funciona también como root).
func breakBackupDir(t *testing.T, tmp string) string {
	t.Helper()
	file := filepath.Join(tmp, "backup-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo backup: %v", err)
	}
	t.Setenv("CADDY_UI_BACKUP_DIR", file)
	return file
}

// breakOverlayWrites hace read-only el managedDir para que el paso de
// escritura atómica falle (EACCES en CreateTemp). Reemplaza la inyección
// histórica del directorio en "<path>.tmp", que desapareció con el contrato
// de temporales únicos de F1 (CreateTemp con sufijo aleatorio ".tmp-*").
// Los permisos se restauran en el cleanup para que t.TempDir pueda limpiar
// el árbol. Como root los permisos no bloquean (EACCES se ignora), el test
// se salta: no hay forma determinista de forzar el fallo de escritura como
// root sin cambiar la superficie pública de la cadena.
func breakOverlayWrites(t *testing.T, managedDir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("EACCES no bloquea a root: imposible forzar el fallo de escritura determinista")
	}
	if err := os.Chmod(managedDir, 0550); err != nil {
		t.Fatalf("fallo haciendo read-only el managedDir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(managedDir, 0750) })
}

// breakOverlayRestore reemplaza el managedDir por un archivo DURANTE la
// recarga (hook onFail del stub): la restauración D6 falla en CreateTemp
// (ENOTDIR), ejercitando el error combinado. El overlay recién escrito queda
// preservado en managedDir+"-moved" para poder asertar su contenido.
func breakOverlayRestore(t *testing.T, env *chainEnv) {
	t.Helper()
	env.admin.onFail = func() {
		moved := env.managedDir + "-moved"
		if err := os.Rename(env.managedDir, moved); err != nil {
			t.Errorf("fallo moviendo managedDir para romper la restauración: %v", err)
			return
		}
		if err := os.WriteFile(env.managedDir, []byte("x"), 0640); err != nil {
			t.Errorf("fallo sembrando archivo managedDir: %v", err)
		}
	}
}

// TestUpdateWAFModeReadErrorFailsBeforeBackup: si el estado previo NO puede
// leerse (ruta es un directorio), la cadena aborta antes de respaldar,
// escribir o recargar, y audita el fallo (W2).
func TestUpdateWAFModeReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "waf-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("fallo sembrando ruta de overlay: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "leyendo estado previo") {
		t.Fatalf("se esperaba error de lectura del estado previo, se obtuvo: %v", err)
	}
	if got := snapshotCount(t, env.backupDir, "api_example_com", "waf"); got != 0 {
		t.Errorf("no deben crearse snapshots si falla la lectura, se encontraron %d", got)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si falla la lectura, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("se esperaba auditoría waf_mode_failed con read error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeBackupFailureDoesNotMutate: si el backup falla, la cadena
// aborta ANTES de escribir: el overlay queda intacto, Caddy no se recarga y el
// evento se audita (W2, rama backup-error del service).
func TestUpdateWAFModeBackupFailureDoesNotMutate(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creando backup") {
		t.Fatalf("se esperaba error de backup, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("el overlay no debe mutar si el backup falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si el backup falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("se esperaba auditoría waf_mode_failed con backup error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeWriteFailureAuditsFailed: si la escritura atómica falla
// (managedDir read-only → EACCES en CreateTemp), la cadena aborta sin recargar
// y audita el fallo (W2, rama write-error del service).
func TestUpdateWAFModeWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error escribiendo configuración") {
		t.Fatalf("se esperaba error de escritura, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("el overlay no debe mutar si la escritura falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si la escritura falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "waf_mode_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("se esperaba auditoría waf_mode_failed con write error:\n%s", audit.String())
	}
}

// TestUpdateWAFModeReloadFailureRestoreError: si la recarga falla Y la
// restauración D6 también (el managedDir es reemplazado por un archivo
// durante la recarga), la cadena reporta AMBOS errores y el overlay queda con
// el contenido nuevo (la reversión no pudo completarse) (W2, restore-error).
func TestUpdateWAFModeReloadFailureRestoreError(t *testing.T) {
	env := setupChainEnv(t, true)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	breakOverlayRestore(t, env)
	audit := captureLogs(t)

	err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restaurando overlay") {
		t.Fatalf("se esperaba error combinado con restore fallido, se obtuvo: %v", err)
	}

	// La reversión no pudo completarse: el overlay con el contenido NUEVO quedó
	// en el dir movido (el managedDir original es ahora un archivo).
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir+"-moved", "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("el overlay con contenido nuevo debe conservarse en el dir movido: %v", readErr)
	}
	if strings.Contains(string(conf), oldWAFContent) {
		t.Errorf("si la restauración falla, el overlay debe conservar el contenido nuevo:\n%s", conf)
	}
	if !strings.Contains(string(conf), "SecRuleEngine On") {
		t.Errorf("el overlay movido debe contener el modo nuevo:\n%s", conf)
	}
	if !strings.Contains(audit.String(), "waf_mode_changed_but_reload_failed") || !strings.Contains(audit.String(), "(restore error:") {
		t.Errorf("se esperaba auditoría con restore error:\n%s", audit.String())
	}
}

// seedOverlayFile escribe un overlay genérico (prefijo tipo) con el contenido
// dado, para ejercitar exclusiones e ip-rules.
func seedOverlayFile(t *testing.T, managedDir, prefix, domain, content string) {
	t.Helper()
	if err := os.WriteFile(
		filepath.Join(managedDir, prefix+"-"+strings.ReplaceAll(strings.ReplaceAll(domain, ".", "_"), "*", "wildcard")+".conf"),
		[]byte(content), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay %s: %v", prefix, err)
	}
}

// TestUpdateExclusionsReadErrorFailsBeforeBackup: mismo contrato de abort temprano
// para la cadena de exclusiones (W2, read-error).
func TestUpdateExclusionsReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("fallo sembrando ruta de overlay: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "leyendo estado previo") {
		t.Fatalf("se esperaba error de lectura, se obtuvo: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si falla la lectura, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("se esperaba auditoría exclusions_failed con read error:\n%s", audit.String())
	}
}

// TestUpdateExclusionsBackupFailureFailsBeforeWrite: fallo de backup deja el
// overlay de exclusiones intacto y audita (W2, backup-error).
func TestUpdateExclusionsBackupFailureFailsBeforeWrite(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previo")
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creando backup") {
		t.Fatalf("se esperaba error de backup, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("el overlay de exclusiones no debe mutar si el backup falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si el backup falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("se esperaba auditoría exclusions_failed con backup error:\n%s", audit.String())
	}
}

// TestUpdateExclusionsReloadFailureRestoresOverlay: fallo de recarga en la
// cadena de exclusiones → D6 restaura el overlay previo y audita (W2).
func TestUpdateExclusionsReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previo")
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateExclusions debería fallar cuando la recarga falla")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("tras el fallo de recarga el overlay debe volver al estado previo (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "exclusions_changed_but_reload_failed") {
		t.Errorf("no se auditó exclusions_changed_but_reload_failed:\n%s", audit.String())
	}
}

// TestUpdateExclusionsWriteFailureAuditsFailed: fallo de escritura atómica en
// la cadena de exclusiones → aborta sin recargar y audita (W2, write-error).
func TestUpdateExclusionsWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "exclusions", "api.example.com", "previo")
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateExclusions("api.example.com",
		[]waf.Exclusion{{Type: waf.ExcludeByID, Value: "941100"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error escribiendo configuración") {
		t.Fatalf("se esperaba error de escritura, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "exclusions-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("el overlay no debe mutar si la escritura falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si la escritura falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "exclusions_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("se esperaba auditoría exclusions_failed con write error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesReadErrorFailsBeforeBackup: mismo contrato de abort temprano
// para la cadena de ip-rules (W2, read-error).
func TestUpdateIPRulesReadErrorFailsBeforeBackup(t *testing.T) {
	env := setupChainEnv(t, false)
	if err := os.MkdirAll(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"), 0750); err != nil {
		t.Fatalf("fallo sembrando ruta de overlay: %v", err)
	}
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "leyendo estado previo") {
		t.Fatalf("se esperaba error de lectura, se obtuvo: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si falla la lectura, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "read error") {
		t.Errorf("se esperaba auditoría iprules_failed con read error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesBackupFailureFailsBeforeWrite: fallo de backup deja el
// overlay de ip-rules intacto y audita (W2, backup-error).
func TestUpdateIPRulesBackupFailureFailsBeforeWrite(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previo")
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creando backup") {
		t.Fatalf("se esperaba error de backup, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("el overlay de ip-rules no debe mutar si el backup falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si el backup falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("se esperaba auditoría iprules_failed con backup error:\n%s", audit.String())
	}
}

// TestUpdateIPRulesReloadFailureRestoresOverlay: fallo de recarga en la cadena
// de ip-rules → D6 restaura el overlay previo y audita (W2).
func TestUpdateIPRulesReloadFailureRestoresOverlay(t *testing.T) {
	env := setupChainEnv(t, true)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previo")
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil {
		t.Fatal("UpdateIPRules debería fallar cuando la recarga falla")
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("tras el fallo de recarga el overlay debe volver al estado previo (D6):\n%s", conf)
	}
	if !strings.Contains(audit.String(), "iprules_changed_but_reload_failed") {
		t.Errorf("no se auditó iprules_changed_but_reload_failed:\n%s", audit.String())
	}
}

// TestUpdateIPRulesWriteFailureAuditsFailed: fallo de escritura atómica en la
// cadena de ip-rules → aborta sin recargar y audita (W2, write-error).
func TestUpdateIPRulesWriteFailureAuditsFailed(t *testing.T) {
	env := setupChainEnv(t, false)
	seedOverlayFile(t, env.managedDir, "ip-rules", "api.example.com", "previo")
	breakOverlayWrites(t, env.managedDir)
	audit := captureLogs(t)

	err := service.UpdateIPRules("api.example.com",
		iprules.IPRules{Denylist: []string{"192.0.2.5"}}, "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error escribiendo configuración") {
		t.Fatalf("se esperaba error de escritura, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "ip-rules-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != "previo" {
		t.Errorf("el overlay no debe mutar si la escritura falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si la escritura falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "iprules_failed") || !strings.Contains(audit.String(), "write error") {
		t.Errorf("se esperaba auditoría iprules_failed con write error:\n%s", audit.String())
	}
}

// TestRollbackBackupFailureFailsBeforeRestore: si el backup del estado actual
// falla, el rollback aborta sin restaurar ni recargar (W2, backup-error).
func TestRollbackBackupFailureFailsBeforeRestore(t *testing.T) {
	env := setupChainEnv(t, false)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error creando backup") {
		t.Fatalf("se esperaba error de backup, se obtuvo: %v", err)
	}

	conf, readErr := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("fallo leyendo overlay: %v", readErr)
	}
	if string(conf) != oldWAFContent {
		t.Errorf("el overlay no debe mutar si el backup del rollback falla:\n%s", conf)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si el backup falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") || !strings.Contains(audit.String(), "backup error") {
		t.Errorf("se esperaba auditoría rollback_failed con backup error:\n%s", audit.String())
	}
}

// TestRollbackRestoreFailureFailsBeforeReload: si la restauración de bytes
// falla (backup dir corrupto: la lectura del snapshot devuelve un error NO
// ErrInvalidBackup), el rollback aborta sin recargar (W2, restore-error).
func TestRollbackRestoreFailureFailsBeforeReload(t *testing.T) {
	env := setupChainEnv(t, false)
	// Sin overlay previo: Backup() no-op (no hay fuente), el fallo ocurre en
	// RestoreBackup al leer desde un backup dir que es un archivo (ENOTDIR).
	breakBackupDir(t, filepath.Dir(env.managedDir))
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2099-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restaurando snapshot") {
		t.Fatalf("se esperaba error de restauración, se obtuvo: %v", err)
	}
	if env.admin.calls != 0 {
		t.Errorf("no debe recargarse Caddy si la restauración falla, se hicieron %d llamadas", env.admin.calls)
	}
	if !strings.Contains(audit.String(), "rollback_failed") || !strings.Contains(audit.String(), "restore error") {
		t.Errorf("se esperaba auditoría rollback_failed con restore error:\n%s", audit.String())
	}
}

// TestRollbackReloadFailureRestoreError: recarga falla + restauración D6
// falla → error combinado y auditoría con restore error (W2, restore-error).
func TestRollbackReloadFailureRestoreError(t *testing.T) {
	env := setupChainEnv(t, true)
	seedWAFOverlay(t, env.managedDir, "api.example.com", oldWAFContent)
	seedBackupSnapshot(t, env.backupDir, "api_example_com", "2020-01-01T00-00-00Z.waf.conf", restoredWAFContent)
	breakOverlayRestore(t, env)
	audit := captureLogs(t)

	err := service.Rollback("api.example.com", "2020-01-01T00-00-00Z.waf.conf", "192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "error restaurando overlay") {
		t.Fatalf("se esperaba error combinado con restore fallido, se obtuvo: %v", err)
	}

	// La reversión no pudo completarse: el overlay con los bytes del snapshot
	// (contenido restaurado) quedó en el dir movido.
	conf, readErr := os.ReadFile(filepath.Join(env.managedDir+"-moved", "waf-api_example_com.conf"))
	if readErr != nil {
		t.Fatalf("el overlay con contenido restaurado debe conservarse en el dir movido: %v", readErr)
	}
	if strings.Contains(string(conf), oldWAFContent) {
		t.Errorf("si la restauración falla, el overlay debe conservar el contenido restaurado:\n%s", conf)
	}
	if !strings.Contains(string(conf), "(restored snippet)") {
		t.Errorf("el overlay movido debe contener los bytes del snapshot restaurado:\n%s", conf)
	}
	if !strings.Contains(audit.String(), "rollback_changed_but_reload_failed") || !strings.Contains(audit.String(), "(restore error:") {
		t.Errorf("se esperaba auditoría con restore error:\n%s", audit.String())
	}
}

// TestDeployContractCustomManagedDirs (hallazgo J5-1): el overlay generado NO
// debe llevar el Include de exclusiones hardcodeado en /etc/caddy/ui-managed.
// Con CADDY_UI_MANAGED_DIR y CADDY_UI_INCLUDE_DIR personalizados, el overlay
// debe referenciar el directorio de inclusión configurado (la vista de Caddy
// del volumen): un despliegue con dirs custom deja de romperse en silencio.
func TestDeployContractCustomManagedDirs(t *testing.T) {
	env := setupChainEnv(t, false)
	t.Setenv("CADDY_UI_INCLUDE_DIR", "/etc/caddy/custom-managed")

	if err := service.UpdateWAFMode("api.example.com", domain.ModeOn, "192.0.2.1"); err != nil {
		t.Fatalf("UpdateWAFMode falló: %v", err)
	}

	conf, err := os.ReadFile(filepath.Join(env.managedDir, "waf-api_example_com.conf"))
	if err != nil {
		t.Fatalf("fallo leyendo overlay: %v", err)
	}
	if !strings.Contains(string(conf), "Include /etc/caddy/custom-managed/exclusions-api_example_com.conf") {
		t.Errorf("el overlay debe referenciar CADDY_UI_INCLUDE_DIR personalizado:\n%s", conf)
	}
	if strings.Contains(string(conf), "Include /etc/caddy/ui-managed/exclusions-api_example_com.conf") {
		t.Errorf("el overlay no debe contener el Include hardcodeado por defecto:\n%s", conf)
	}
	if env.admin.calls != 1 {
		t.Errorf("se esperaba 1 recarga, se hicieron %d", env.admin.calls)
	}
}
