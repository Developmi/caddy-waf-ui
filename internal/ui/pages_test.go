package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/logs"
)

// TestLogPageURLPreservesFilters verifica que los enlaces del pager conserven
// los filtros activos del explorador (tab/search/actionFilter) y no emitan
// enlaces fuera de rango.
func TestLogPageURLPreservesFilters(t *testing.T) {
	q := url.Values{"search": {"1.2.3.4"}, "actionFilter": {"BLOCKED"}}

	got := logPageURL(q, 2)
	// url.Values.Encode ordena alfabéticamente: actionFilter, page, search, tab.
	want := "/?actionFilter=BLOCKED&page=2&search=1.2.3.4&tab=logs"
	if got != want {
		t.Errorf("se esperaba %q, se obtuvo %q", want, got)
	}

	if got := logPageURL(q, 0); got != "" {
		t.Errorf("page=0 no debe producir enlace (fuera de rango), se obtuvo %q", got)
	}
	if got := logPageURL(url.Values{}, 1); got != "/?page=1&tab=logs" {
		t.Errorf("sin filtros solo debe llevar tab y page, se obtuvo %q", got)
	}
}

// TestLogsPageRendersPager verifica que el pager se renderice con la página
// actual y los enlaces prev/next, y que las entradas de la tabla se muestren.
func TestLogsPageRendersPager(t *testing.T) {
	data := pageData{
		ActiveTab:    "logs",
		Logs:         []logs.AuditEntry{{RuleID: "942100", Client: "1.2.3.4", Action: "BLOCKED"}},
		LogPage:      2,
		LogPages:     3,
		LogPrevURL:   "/?tab=logs&page=1",
		LogNextURL:   "/?tab=logs&page=3",
		LogSearch:    "1.2.3.4",
		ActionFilter: "BLOCKED",
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "logs", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(body, "Page 2 of 3") {
		t.Errorf("el pager debe mostrar la página actual y el total: %s", body)
	}
	// html/template escapa & como &amp; en contexto de atributo.
	if !strings.Contains(body, `href="/?tab=logs&amp;page=1"`) || !strings.Contains(body, `href="/?tab=logs&amp;page=3"`) {
		t.Errorf("el pager debe enlazar prev y next: %s", body)
	}
	if !strings.Contains(body, "942100") || !strings.Contains(body, "1.2.3.4") {
		t.Errorf("la tabla debe renderizar las entradas de la página: %s", body)
	}
}

// TestLogsPageWithoutPagerRendersNoPager verifica que con una sola página el
// pager no se renderice (rama negativa del template).
func TestLogsPageWithoutPagerRendersNoPager(t *testing.T) {
	data := pageData{
		ActiveTab: "logs",
		Logs:      []logs.AuditEntry{{RuleID: "942100"}},
		LogPage:   1,
		LogPages:  1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "logs", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, "Page 1 of 1") {
		t.Errorf("con una sola página el pager no debe renderizarse: %s", body)
	}
	if !strings.Contains(body, "942100") {
		t.Errorf("la tabla debe seguir renderizando la entrada: %s", body)
	}
}

// seedRollbackEnv prepara managedDir + backupDir con un overlay registrado y
// snapshots opcionales para el tab rollback.
func seedRollbackEnv(t *testing.T, snapshots map[string]string) {
	t.Helper()
	managedDir := t.TempDir()
	backupDir := t.TempDir()
	t.Setenv("CADDY_UI_MANAGED_DIR", managedDir)
	t.Setenv("CADDY_UI_BACKUP_DIR", backupDir)

	overlay := filepath.Join(managedDir, "waf-api_example_com.conf")
	if err := os.WriteFile(overlay, []byte("# domain: api.example.com | mode: On | updated: 2026-08-07T00:00:00Z\n"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	for name, content := range snapshots {
		slugDir := filepath.Join(backupDir, "api_example_com")
		if err := os.MkdirAll(slugDir, 0750); err != nil {
			t.Fatalf("fallo creando dir de backups: %v", err)
		}
		if err := os.WriteFile(filepath.Join(slugDir, name), []byte(content), 0640); err != nil {
			t.Fatalf("fallo sembrando snapshot %s: %v", name, err)
		}
	}
}

// TestRollbackTabRendersSnapshots: el tab rollback debe cargar los snapshots
// reales del dominio (files.ListBackups) y renderizar la fila de restauración
// con el formulario PRG (action + snapId) (spec backup-recovery).
func TestRollbackTabRendersSnapshots(t *testing.T) {
	seedRollbackEnv(t, map[string]string{
		"2020-01-01T00-00-00Z.waf.conf": "v1",
	})

	req := httptest.NewRequest(http.MethodGet, "/?tab=rollback&domain=api.example.com", nil)
	data := buildPageData(req, "rollback", scanSites())
	if len(data.Snapshots) != 1 {
		t.Fatalf("se esperaba 1 snapshot cargado del listado real, se obtuvieron %d", len(data.Snapshots))
	}
	if data.Snapshots[0].FileType != "waf" {
		t.Errorf("el snapshot cargado debe conservar su tipo: %+v", data.Snapshots[0])
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "rollback", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(body, "2020-01-01T00-00-00Z") {
		t.Errorf("la línea de tiempo debe mostrar el timestamp del snapshot: %s", body)
	}
	if !strings.Contains(body, `action="/sites/api.example.com/rollback"`) {
		t.Errorf("cada snapshot debe tener su formulario de restauración PRG: %s", body)
	}
	if !strings.Contains(body, `name="snapId" value="2020-01-01T00-00-00Z.waf.conf"`) {
		t.Errorf("el formulario debe enviar el nombre completo del snapshot: %s", body)
	}
	if !strings.Contains(body, "Restore This Snapshot") {
		t.Errorf("debe existir el botón de restauración: %s", body)
	}
}

// TestRollbackTabEmptyState: sin backups el tab rollback renderiza el estado
// vacío honesto (spec backup-recovery: "empty state"), nunca 500.
func TestRollbackTabEmptyState(t *testing.T) {
	seedRollbackEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/?tab=rollback&domain=api.example.com", nil)
	data := buildPageData(req, "rollback", scanSites())
	if len(data.Snapshots) != 0 {
		t.Fatalf("sin backups se esperaba lista vacía, se obtuvieron %d", len(data.Snapshots))
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "rollback", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("sin backups se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(body, "No configuration snapshots created yet for this domain.") {
		t.Errorf("sin backups debe renderizar el estado vacío honesto: %s", body)
	}
	if strings.Contains(body, "Restore This Snapshot") {
		t.Errorf("sin snapshots no debe haber botones de restauración: %s", body)
	}
}

// TestOverviewRendersDegradedBadge: un sitio con Degraded=true (modo de
// cabecera desconocido) debe mostrar el badge "degraded" en la fila de la
// tabla del overview (W1) - la UI nunca debe presentar un modo inventado.
func TestOverviewRendersDegradedBadge(t *testing.T) {
	data := pageData{
		ActiveTab: "overview",
		Sites: []*domain.Site{
			{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true},
			{Domain: "web.example.com", Mode: domain.ModeOn},
		},
		SitesOn:        1,
		SitesDetection: 1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "overview", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	// El badge visible es el span con el texto "degraded" (la clase CSS
	// .badge-degraded siempre está en el <style> - no es evidencia de render).
	if !strings.Contains(body, ">degraded<") {
		t.Errorf("el sitio degradado debe mostrar el badge 'degraded': %s", body)
	}
}

// TestOverviewHidesDegradedBadgeForHealthySites (triangulación): los sitios
// con modo válido NO llevan badge degradado.
func TestOverviewHidesDegradedBadgeForHealthySites(t *testing.T) {
	data := pageData{
		ActiveTab: "overview",
		Sites:     []*domain.Site{{Domain: "web.example.com", Mode: domain.ModeOn}},
		SitesOn:   1,
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "overview", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	if body := rec.Body.String(); strings.Contains(body, ">degraded<") {
		t.Errorf("un sitio sano no debe mostrar el badge degradado: %s", body)
	}
}

// TestSitesRendersDegradedBadge: la vista sites (dominio actual) también debe
// exponer el badge cuando el sitio está degradado (W1).
func TestSitesRendersDegradedBadge(t *testing.T) {
	data := pageData{
		ActiveTab:   "sites",
		Sites:       []*domain.Site{{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true}},
		CurrentSite: &domain.Site{Domain: "api.example.com", Mode: domain.ModeDetectionOnly, Degraded: true},
	}

	rec := httptest.NewRecorder()
	if err := executePage(rec, "sites", data); err != nil {
		t.Fatalf("render falló: %v", err)
	}
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(body, ">degraded<") {
		t.Errorf("la vista sites debe mostrar el badge 'degraded': %s", body)
	}
}

// findCookie localiza una cookie por nombre en la respuesta (helpers de los
// tests de flash one-shot).
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestOverviewScanFailureRendersEmptyState: si el scan de overlays falla
// (managed dir corrupto), la vista overview responde 200 con el estado vacío
// honesto y el flash traducido - nunca 500 (W2, rama scanSites-error de pages).
// El flash se consume one-shot: el ?flash= redirige a una URL limpia con la
// cookie efímera, y el render consume y borra la cookie (refresh no re-muestra).
func TestOverviewScanFailureRendersEmptyState(t *testing.T) {
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	for flash, want := range map[string]string{
		"success":           "Configuration updated successfully.",
		"error":             "The configuration could not be applied.",
		"logged_out":        "You have been signed out.",
		"clave-desconocida": "clave-desconocida", // flashMessage default: la clave pasa tal cual
	} {
		// Primer GET con ?flash= (PRG): consume con redirect limpio + cookie.
		req := httptest.NewRequest(http.MethodGet, "/?flash="+flash, nil)
		rec := httptest.NewRecorder()
		HandleIndex(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("flash=%s: el consumo one-shot debe redirigir, se obtuvo %d", flash, rec.Code)
		}
		if loc := rec.Header().Get("Location"); strings.Contains(loc, "flash=") {
			t.Errorf("flash=%s: el redirect de consumo debe quitar ?flash=, se obtuvo %q", flash, loc)
		}
		cookie := findCookie(rec.Result().Cookies(), flashCookieName)
		if cookie == nil {
			t.Fatalf("flash=%s: el redirect debe fijar la cookie efímera del flash", flash)
		}

		// Segundo GET: render con toast tipado y cookie consumida (borrada).
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.AddCookie(cookie)
		rec2 := httptest.NewRecorder()
		HandleIndex(rec2, req2)

		if rec2.Code != http.StatusOK {
			t.Fatalf("flash=%s: se esperaba 200 con estado vacío, se obtuvo %d", flash, rec2.Code)
		}
		body := rec2.Body.String()
		if !strings.Contains(body, "No managed domains registered yet.") {
			t.Errorf("flash=%s: el overview debe renderizar el estado vacío honesto", flash)
		}
		if !strings.Contains(body, want) {
			t.Errorf("flash=%s: el toast debe mostrar %q, se obtuvo: %s", flash, want, body)
		}
		if del := findCookie(rec2.Result().Cookies(), flashCookieName); del == nil || del.MaxAge >= 0 {
			t.Errorf("flash=%s: el render debe borrar la cookie del flash (one-shot)", flash)
		}
		// Tipado (fix J3-1): error → rojo con role=alert; resto → verde role=status.
		if flash == "error" {
			if !strings.Contains(body, `class="toast-notice toast-notice--error"`) || !strings.Contains(body, `role="alert"`) {
				t.Errorf("flash=error debe renderizarse como alerta (rojo + role=alert): %s", body)
			}
		} else if !strings.Contains(body, `role="status"`) {
			t.Errorf("flash=%s debe renderizarse como éxito (verde + role=status): %s", flash, body)
		}
	}
}

// TestHandleIndexRendersOverview: con entorno sano, GET / renderiza el
// overview (200) a través del mux de páginas (W2, rama principal de HandleIndex).
func TestHandleIndexRendersOverview(t *testing.T) {
	seedRollbackEnv(t, nil)
	mux := NewPagesMux()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Managed Per-Site WAF Domains") || !strings.Contains(body, "Caddy WAF UI") {
		t.Errorf("el overview no se renderizó completo: %s", body)
	}
}

// TestHandleLoginPageWithoutSessionRendersForm: GET /login sin sesión
// renderiza el formulario (200). El flash one-shot redirige primero a una URL
// limpia y se consume en el render siguiente.
func TestHandleLoginPageWithoutSessionRendersForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login?flash=invalid_login", nil)
	rec := httptest.NewRecorder()
	HandleLoginPage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("el consumo one-shot del flash debe redirigir, se obtuvo %d", rec.Code)
	}
	cookie := findCookie(rec.Result().Cookies(), flashCookieName)
	if cookie == nil {
		t.Fatal("el redirect de consumo debe fijar la cookie efímera del flash")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	HandleLoginPage(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec2.Code)
	}
	body := rec2.Body.String()
	if !strings.Contains(body, "Invalid access token.") {
		t.Errorf("el flash invalid_login debe traducirse en el login: %s", body)
	}
}

// TestHandleLoginPageWithSessionRedirects: con sesión válida, /login
// redirige a / (302).
func TestHandleLoginPageWithSessionRedirects(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "CADDY_UI_TOKEN", Value: "super-secret-token", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	HandleLoginPage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("se esperaba 302 con sesión válida, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("se esperaba Location /, se obtuvo %q", loc)
	}
}

// TestExecutePageUnknownTemplateError: una plantilla desconocida produce error
// (rama de executePage) y el handler responde 500.
func TestExecutePageUnknownTemplateError(t *testing.T) {
	rec := httptest.NewRecorder()
	err := executePage(rec, "no-existe", pageData{})
	if err == nil {
		t.Fatal("una plantilla desconocida debe devolver error")
	}

	rec2 := httptest.NewRecorder()
	HandleIndex(rec2, httptest.NewRequest(http.MethodGet, "/?tab=no-existe", nil))
	if rec2.Code != http.StatusInternalServerError {
		t.Errorf("tab desconocido debe responder 500, se obtuvo %d", rec2.Code)
	}
}

// TestLoadLogsErrorBranchReturnsEmpty: sin archivo de audit log, loadLogs
// devuelve página vacía (estado vacío honesto del tab logs).
func TestLoadLogsErrorBranchReturnsEmpty(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join(t.TempDir(), "no-existe.log"))
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	data := buildPageData(req, "logs", nil)

	if len(data.Logs) != 0 || data.LogPages != 0 {
		t.Errorf("sin audit log debe quedar estado vacío, se obtuvo %d entradas / %d páginas", len(data.Logs), data.LogPages)
	}
}

// TestLoadLogsSuccessPopulatesEntries (triangulación): con audit log real el
// tab logs se alimenta de las entradas.
func TestLoadLogsSuccessPopulatesEntries(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join("..", "logs", "testdata", "audit-valid.jsonl"))
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())
	t.Setenv("CADDY_UI_BACKUP_DIR", t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	data := buildPageData(req, "logs", nil)

	if len(data.Logs) == 0 {
		t.Fatal("con audit log real el tab logs debe cargar entradas")
	}
	if data.LogPages < 1 {
		t.Errorf("con entradas debe existir al menos 1 página, se obtuvo %d", data.LogPages)
	}
}
