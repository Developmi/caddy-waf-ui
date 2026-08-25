package integration_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

// setupSSR prepara el entorno completo (token, directorios, stub de la Admin
// API) y ensambla el mux con los tres grupos de rutas EXACTAMENTE como lo
// hace cmd/server/main.go (task 2.7): público (login), páginas SSR (sesión
// por cookie o Bearer + CSRF) y API RESTful (Bearer-pura).
func setupSSR(t *testing.T, admin *adminStub) http.Handler {
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

	mux := http.NewServeMux()
	mux.Handle("/login", ui.NewLoginMux())
	api := auth.Middleware(ui.NewRouter())
	mux.Handle("/api/", api)
	mux.Handle("/health", api)
	mux.Handle("/", auth.Session(auth.CSRF(ui.NewPagesMux())))
	return mux
}

// sessionCookie devuelve una cookie válida como la que fija POST /login.
func sessionCookie() *http.Cookie {
	return &http.Cookie{Name: "CADDY_UI_TOKEN", Value: "super-secret-token", Path: "/"}
}

// formRequest construye un POST urlencoded con cookie opcional.
func formRequest(t *testing.T, method, path string, form url.Values, cookie *http.Cookie) *http.Request {
	req, err := http.NewRequest(method, path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("fallo creando request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

// csrfValue deriva el token CSRF del entorno de prueba (D1).
func csrfValue(t *testing.T) string {
	token, err := auth.CSRFValue()
	if err != nil {
		t.Fatalf("fallo derivando token CSRF: %v", err)
	}
	return token
}

func TestSSRLoginSetsSessionCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"token": {"super-secret-token"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/login", form, nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 tras login válido, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("se esperaba redirección a /, se obtuvo %q", loc)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "CADDY_UI_TOKEN=super-secret-token") {
		t.Errorf("la cookie no transporta el token: %q", setCookie)
	}
	for _, flag := range []string{"HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(setCookie, flag) {
			t.Errorf("la cookie de sesión no lleva el flag %s: %q", flag, setCookie)
		}
	}
}

func TestSSRLoginRejectsWrongToken(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"token": {"token-incorrecto"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/login", form, nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 tras login inválido, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("se esperaba redirección con flash=invalid_login, se obtuvo %q", loc)
	}
	if setCookie := rec.Header().Get("Set-Cookie"); strings.Contains(setCookie, "CADDY_UI_TOKEN=") {
		t.Errorf("no debe fijarse cookie con credencial inválida: %q", setCookie)
	}
}

func TestSSRPageWithoutSessionRedirectsToLogin(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	for _, path := range []string{"/", "/?tab=logs", "/?tab=sites"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusFound {
			t.Errorf("%s: se esperaba 302 sin sesión, se obtuvo %d", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: se esperaba Location /login, se obtuvo %q", path, loc)
		}
	}
}

func TestSSRIndexRendersWithCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 con cookie de sesión, se obtuvo %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Caddy WAF UI") {
		t.Errorf("el HTML no contiene la marca de la UI")
	}
	if !strings.Contains(body, "?tab=sites") {
		t.Errorf("el HTML no contiene la navegación por pestañas")
	}
}

func TestSSRIndexAcceptsBearer(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200 con Bearer válido, se obtuvo %d", rec.Code)
	}
}

func TestSSRIndexEscapesDomainValue(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	// Un dominio con <script> registrado desde la cabecera de un overlay:
	// html/template debe escaparlo en contexto de texto (spec web-ui).
	overlay := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-<script>_com.conf")
	if err := os.WriteFile(overlay, []byte("# domain: <script>.com | mode: On | updated: 2026-08-07T00:00:00Z\n"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "&lt;script&gt;.com") {
		t.Errorf("el dominio debe renderizarse escapado (&lt;script&gt;.com)")
	}
	if strings.Contains(body, "<script>.com") {
		t.Errorf("el dominio no debe aparecer crudo en el HTML")
	}
}

func TestSSRPRGModeChangeSuccess(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"mode":   {"On"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location inválida: %v", err)
	}
	q := loc.Query()
	if q.Get("flash") != "success" {
		t.Errorf("se esperaba flash=success, se obtuvo %q", q.Get("flash"))
	}
	if q.Get("tab") != "sites" || q.Get("domain") != "example.com" {
		t.Errorf("la redirección debe preservar tab y domain: %s", rec.Header().Get("Location"))
	}

	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("no se escribió el overlay tras el POST: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("el overlay no refleja el modo enviado:\n%s", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("se esperaba 1 recarga de Caddy, se hicieron %d", admin.reloads)
	}
}

func TestSSRPRGModeChangeInvalidNoMutation(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"mode":   {"ModoInexistente"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	if q := url.QueryEscape("flash=error"); !strings.Contains(rec.Header().Get("Location"), q) {
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "flash=error") {
			t.Errorf("se esperaba flash=error, se obtuvo %q", loc)
		}
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("un POST inválido no debe mutar estado: el overlay no debe existir")
	}
	if admin.reloads != 0 {
		t.Errorf("un POST inválido no debe recargar Caddy, se hicieron %d recargas", admin.reloads)
	}
}

func TestSSRCSRFMissingTokenRejected(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 sin token CSRF, se obtuvo %d", rec.Code)
	}
}

func TestSSRCSRFWrongTokenRejected(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{
		"mode":   {"On"},
		"tab":    {"sites"},
		"domain": {"example.com"},
		"csrf":   {"token-incorrecto"},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/mode", form, sessionCookie()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("se esperaba 403 con token CSRF inválido, se obtuvo %d", rec.Code)
	}
}

func TestSSRCSRFBearerExempt(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	// Los requests autenticados por Bearer no pueden ser emitidos cross-site
	// por un navegador (D1): quedan exentos del chequeo CSRF.
	form := url.Values{"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"}}
	req := formRequest(t, http.MethodPost, "/sites/example.com/mode", form, nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 con Bearer (exento de CSRF), se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("se esperaba flash=success, se obtuvo %q", rec.Header().Get("Location"))
	}
	if admin.reloads != 1 {
		t.Errorf("se esperaba 1 recarga, se hicieron %d", admin.reloads)
	}
}

// auditFixture devuelve la ruta del fixture JSONL del lector (misma fuente
// que los tests unitarios de internal/logs).
func auditFixture() string {
	return filepath.Join("..", "..", "internal", "logs", "testdata", "audit-valid.jsonl")
}

// TestSSRLogsTabRendersFilteredEntries: el tab Logs debe alimentarse del audit
// log REAL (spec audit-logs) y aplicar actionFilter + search server-side.
func TestSSRLogsTabRendersFilteredEntries(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	req := httptest.NewRequest(http.MethodGet, "/?tab=logs&actionFilter=BLOCKED&search=1.2.3.4", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "942100") {
		t.Errorf("la entrada bloqueada (942100) debe renderizarse")
	}
	if !strings.Contains(body, "/wp-admin/login.php") {
		t.Errorf("la URI de la entrada bloqueada debe renderizarse")
	}
	if strings.Contains(body, "920420") {
		t.Errorf("actionFilter=BLOCKED debe excluir la entrada detectada (920420)")
	}
	if strings.Contains(body, "203.0.113.9") {
		t.Errorf("search=1.2.3.4 debe excluir la entrada del cliente 203.0.113.9")
	}
	if strings.Contains(body, "No Coraza audit logs found") {
		t.Errorf("con resultados el estado vacío no debe renderizarse")
	}
}

// TestSSRLogsTabSearchMatchesAnyField: el search es case-insensitive y cubre
// client/uri/ruleID/message (placeholder del template).
func TestSSRLogsTabSearchMatchesAnyField(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	// URI en mayúsculas: debe matchear /wp-admin/login.php.
	req := httptest.NewRequest(http.MethodGet, "/?tab=logs&search=WP-ADMIN", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("se esperaba 200, se obtuvo %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "942100") {
		t.Errorf("search=WP-ADMIN debe matchear la entrada 942100 (case-insensitive)")
	}
	if strings.Contains(body, "920420") {
		t.Errorf("search=WP-ADMIN no debe traer la entrada 920420")
	}
}

// TestSSRLogsTabEmptyState: búsqueda sin resultados y archivo ausente
// renderizan el estado vacío honesto (200, nunca 500).
func TestSSRLogsTabEmptyState(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", auditFixture())
	handler := setupSSR(t, &adminStub{})

	for _, path := range []string{"/?tab=logs&search=zzz-no-existe", "/?tab=logs&search=zzz-no-existe&actionFilter=BLOCKED"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(sessionCookie())
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: se esperaba 200, se obtuvo %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "No Coraza audit logs found") {
			t.Errorf("%s: sin resultados debe renderizar el estado vacío", path)
		}
	}

	// Archivo ausente (primer arranque del sidecar): warn + estado vacío.
	t.Setenv("CADDY_UI_AUDIT_LOG", filepath.Join(t.TempDir(), "no-existe.log"))
	req := httptest.NewRequest(http.MethodGet, "/?tab=logs", nil)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sin archivo de audit log se esperaba 200 con estado vacío, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No Coraza audit logs found") {
		t.Errorf("sin archivo de audit log debe renderizar el estado vacío")
	}
}

func TestSSRLogoutClearsSessionCookie(t *testing.T) {
	handler := setupSSR(t, &adminStub{})

	form := url.Values{"csrf": {csrfValue(t)}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/logout", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 tras logout, se obtuvo %d", rec.Code)
	}
	setCookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "CADDY_UI_TOKEN=") {
		t.Fatalf("logout debe emitir una cookie de expiración: %q", setCookie)
	}

	// Tras el logout, la sesión ya no es válida: la página vuelve a redirigir.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec2.Code != http.StatusFound || rec2.Header().Get("Location") != "/login" {
		t.Errorf("tras logout, GET / debe redirigir a /login (302), se obtuvo %d %q", rec2.Code, rec2.Header().Get("Location"))
	}
}

// TestSSRPRGRollbackSuccess: POST /sites/{domain}/rollback restaura el
// snapshot (PRG 303 + flash) y el overlay vuelve a los bytes del snapshot.
func TestSSRPRGRollbackSuccess(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	slugDir := filepath.Join(os.Getenv("CADDY_UI_BACKUP_DIR"), "example_com")
	if err := os.MkdirAll(slugDir, 0750); err != nil {
		t.Fatalf("fallo creando dir de backups: %v", err)
	}
	if err := os.WriteFile(filepath.Join(slugDir, "2020-01-01T00-00-00Z.waf.conf"), []byte("estado restaurado"), 0640); err != nil {
		t.Fatalf("fallo sembrando snapshot: %v", err)
	}

	form := url.Values{
		"snapId": {"2020-01-01T00-00-00Z.waf.conf"},
		"tab":    {"rollback"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=success") {
		t.Errorf("se esperaba flash=success, se obtuvo %q", loc)
	}
	if !strings.Contains(loc, "tab=rollback") {
		t.Errorf("la redirección debe preservar la pestaña rollback: %q", loc)
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("no se restauró el overlay: %v", err)
	}
	if string(overlay) != "estado restaurado" {
		t.Errorf("el overlay debe contener los bytes del snapshot: %q", overlay)
	}
	if admin.reloads != 1 {
		t.Errorf("se esperaba 1 recarga de Caddy, se hicieron %d", admin.reloads)
	}
}

// TestSSRPRGRollbackInvalidNoMutation: un snapshot inválido devuelve 303
// ?flash=error sin mutar el overlay ni recargar Caddy (fail-fast).
func TestSSRPRGRollbackInvalidNoMutation(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}

	form := url.Values{
		"snapId": {"../../etc/passwd"},
		"tab":    {"rollback"},
		"domain": {"example.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/example.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("se esperaba flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}

	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("fallo leyendo overlay: %v", err)
	}
	if string(overlay) != "estado actual" {
		t.Errorf("un snapshot inválido no debe mutar el overlay: %q", overlay)
	}
	if admin.reloads != 0 {
		t.Errorf("un snapshot inválido no debe recargar Caddy, se hicieron %d recargas", admin.reloads)
	}
}

// TestSSRFormRollbackMissingDomainFlashError: un POST hacia un dominio SIN
// overlay ni snapshots (dominio inexistente en el registry) responde 303
// ?flash=error a través del stack completo (sesión + CSRF), sin mutar nada ni
// recargar Caddy (W2, rama de error del form con dominio ausente).
func TestSSRFormRollbackMissingDomainFlashError(t *testing.T) {
	admin := &adminStub{}
	handler := setupSSR(t, admin)

	form := url.Values{
		"snapId": {"2099-01-01T00-00-00Z.waf.conf"}, // nombre canónico, snapshot inexistente
		"tab":    {"rollback"},
		"domain": {"no-such-domain.com"},
		"csrf":   {csrfValue(t)},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, formRequest(t, http.MethodPost, "/sites/no-such-domain.com/rollback", form, sessionCookie()))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("dominio sin snapshots debe redirigir con flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-no_such_domain_com.conf")); !os.IsNotExist(err) {
		t.Errorf("un rollback fallido no debe crear overlays para el dominio")
	}
	if admin.reloads != 0 {
		t.Errorf("un rollback fallido no debe recargar Caddy, se hicieron %d recargas", admin.reloads)
	}
}
