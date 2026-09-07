package ui

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formPost construye un POST urlencoded hacia el mux indicado.
func formPost(t *testing.T, mux *http.ServeMux, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestRedirectAfterFormPreservesQuery: el patrón PRG conserva
// tab/domain/search/actionFilter y agrega flash (spec web-ui).
func TestRedirectAfterFormPreservesQuery(t *testing.T) {
	form := url.Values{
		"tab":          {"sites"},
		"domain":       {"example.com"},
		"search":       {"1.2.3.4"},
		"actionFilter": {"BLOCKED"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sites/example.com/mode", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	redirectAfterForm(rec, req, "success")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	q, err := url.ParseQuery(strings.TrimPrefix(loc, "/?"))
	if err != nil {
		t.Fatalf("Location inválida: %q", loc)
	}
	for key, want := range map[string]string{
		"tab": "sites", "domain": "example.com", "search": "1.2.3.4", "actionFilter": "BLOCKED", "flash": "success",
	} {
		if q.Get(key) != want {
			t.Errorf("la redirección debe preservar %s=%q, se obtuvo %q (Location=%q)", key, want, q.Get(key), loc)
		}
	}
}

// TestHandleLoginSuccess: token válido fija cookie y redirige a /.
func TestHandleLoginSuccess(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	mux := NewLoginMux()

	rec := formPost(t, mux, "/login", url.Values{"token": {"super-secret-token"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("se esperaba redirección a /, se obtuvo %q", loc)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("login válido debe fijar la cookie de sesión: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLoginInvalidToken: token incorrecto → flash=invalid_login sin cookie.
func TestHandleLoginInvalidToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")
	mux := NewLoginMux()

	rec := formPost(t, mux, "/login", url.Values{"token": {"token-incorrecto"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("se esperaba flash=invalid_login, se obtuvo %q", loc)
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("credencial inválida no debe fijar cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLogout: invalida la cookie y redirige al login con flash.
func TestHandleLogout(t *testing.T) {
	mux := NewPagesMux()

	rec := formPost(t, mux, "/logout", url.Values{})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=logged_out") {
		t.Errorf("se esperaba flash=logged_out, se obtuvo %q", loc)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "CADDY_UI_TOKEN=") {
		t.Errorf("logout debe emitir cookie de expiración: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestHandleLoginInvalidTokenEmitsSecurityWarn (LE-1/D10): un POST /login con
// token inválido emite un slog.Warn de seguridad que incluye el RemoteAddr
// del cliente, y conserva el PRG 303 ?flash=invalid_login. El evento usa
// slog directo (msg "login rechazado", key remote_ip): NUNCA se loguea como
// ui_request (D2) ni se registra material de la credencial.
func TestHandleLoginInvalidTokenEmitsSecurityWarn(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token=token-incorrecto"))
	req.RemoteAddr = "203.0.113.77:5555"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	NewLoginMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303 (PRG), se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=invalid_login") {
		t.Errorf("se esperaba flash=invalid_login, se obtuvo %q", loc)
	}

	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "login rechazado") {
		t.Errorf("el login fallido debe emitir slog.Warn \"login rechazado\", buffer:\n%s", out)
	}
	if !strings.Contains(out, "remote_ip=203.0.113.77:5555") {
		t.Errorf("el Warn debe incluir remote_ip con el RemoteAddr del cliente, buffer:\n%s", out)
	}
	if strings.Contains(out, "token-incorrecto") {
		t.Errorf("la credencial provista no debe aparecer en el log, buffer:\n%s", out)
	}
}

// TestHandleLoginSuccessSilentNoWarn (LE-1): el login válido NO emite el
// evento de seguridad (éxito silencioso) ni credencial alguna en el log.
func TestHandleLoginSuccessSilentNoWarn(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(prev)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("token=super-secret-token"))
	req.RemoteAddr = "203.0.113.77:5555"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	NewLoginMux().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("se esperaba redirección a /, se obtuvo %q", loc)
	}

	out := buf.String()
	if out != "" {
		t.Errorf("el login válido debe ser silencioso (sin Warn ni credenciales), buffer:\n%s", out)
	}
}

// TestHandleFormSetModeSuccess: POST válido → 303 flash=success y overlay
// regenerado (PRG, spec web-ui).
func TestHandleFormSetModeSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/mode", url.Values{
		"mode": {"On"}, "tab": {"sites"}, "domain": {"example.com"},
	})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("se esperaba flash=success, se obtuvo %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf"))
	if err != nil {
		t.Fatalf("no se escribió el overlay: %v", err)
	}
	if !strings.Contains(string(overlay), "SecRuleEngine On") {
		t.Errorf("el overlay no refleja el modo enviado:\n%s", overlay)
	}
}

// TestHandleFormSetModeInvalidModeFlashError: modo inválido → flash=error sin
// mutar nada (el servicio valida antes del backup).
func TestHandleFormSetModeInvalidModeFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/mode", url.Values{"mode": {"BlockAll"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("se esperaba flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")); !os.IsNotExist(err) {
		t.Errorf("un modo inválido no debe crear el overlay")
	}
}

// TestHandleFormAddExclusionReadErrorFlashError: si el estado activo no puede
// leerse (managed dir corrupto - dominio sin overlay legible), el POST de
// exclusión falla con flash=error en vez de reemplazar la lista a ciegas (W2,
// rama readExclusions-error de forms.go).
func TestHandleFormAddExclusionReadErrorFlashError(t *testing.T) {
	setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/exclusions", url.Values{"ruleId": {"941100"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("fallo de lectura debe redirigir con flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddExclusionSuccess: exclusión nueva fusionada con el estado
// actual → 303 flash=success (PRG).
func TestHandleFormAddExclusionSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/exclusions", url.Values{"ruleId": {"941100"}, "param": {"q"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("se esperaba flash=success, se obtuvo %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "exclusions-example_com.conf"))
	if err != nil {
		t.Fatalf("no se escribió el overlay: %v", err)
	}
	if !strings.Contains(string(overlay), "ARGS:q") || !strings.Contains(string(overlay), "9000001") {
		t.Errorf("el overlay no contiene la exclusión targeteada:\n%s", overlay)
	}
}

// TestHandleFormAddIPRuleInvalidActionFlashError: acción desconocida → flash
// de error sin mutar (rama default de forms.go).
func TestHandleFormAddIPRuleInvalidActionFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"BAN"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("acción inválida debe redirigir con flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddIPRuleReadErrorFlashError: si el estado actual no puede
// leerse, el POST de regla IP falla con flash=error (W2, rama readIPRules-error).
func TestHandleFormAddIPRuleReadErrorFlashError(t *testing.T) {
	setupUIEnv(t)
	file := filepath.Join(t.TempDir(), "managed-es-un-archivo")
	if err := os.WriteFile(file, []byte("x"), 0640); err != nil {
		t.Fatalf("fallo sembrando archivo: %v", err)
	}
	t.Setenv("CADDY_UI_MANAGED_DIR", file)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"DENY"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("fallo de lectura debe redirigir con flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
}

// TestHandleFormAddIPRuleSuccess: regla DENY fusionada → 303 flash=success.
func TestHandleFormAddIPRuleSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	rec := formPost(t, mux, "/sites/example.com/iprules", url.Values{"cidr": {"192.0.2.5"}, "action": {"DENY"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=success") {
		t.Errorf("se esperaba flash=success, se obtuvo %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "ip-rules-example_com.conf"))
	if err != nil {
		t.Fatalf("no se escribió el overlay: %v", err)
	}
	if !strings.Contains(string(overlay), "192.0.2.5/32") {
		t.Errorf("el overlay no contiene la IP normalizada:\n%s", overlay)
	}
}

// TestHandleFormRollbackSuccess: rollback PRG exitoso → 303 flash=success.
func TestHandleFormRollbackSuccess(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}
	seedUISnapshot(t, "example_com", "2020-01-01T00-00-00Z.waf.conf", "estado restaurado")

	rec := formPost(t, mux, "/sites/example.com/rollback", url.Values{"snapId": {"2020-01-01T00-00-00Z.waf.conf"}, "tab": {"rollback"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "flash=success") || !strings.Contains(loc, "tab=rollback") {
		t.Errorf("se esperaba flash=success preservando la pestaña, se obtuvo %q", loc)
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("no se restauró el overlay: %v", err)
	}
	if string(overlay) != "estado restaurado" {
		t.Errorf("el overlay debe contener los bytes del snapshot: %q", overlay)
	}
}

// TestHandleFormRollbackInvalidSnapshotFlashError: snapshot inseguro →
// flash=error sin mutar (fail-fast del servicio).
func TestHandleFormRollbackInvalidSnapshotFlashError(t *testing.T) {
	setupUIEnv(t)
	mux := NewPagesMux()

	overlayPath := filepath.Join(os.Getenv("CADDY_UI_MANAGED_DIR"), "waf-example_com.conf")
	if err := os.WriteFile(overlayPath, []byte("estado actual"), 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}

	rec := formPost(t, mux, "/sites/example.com/rollback", url.Values{"snapId": {"../../etc/passwd"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("se esperaba 303, se obtuvo %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "flash=error") {
		t.Errorf("snapshot inválido debe redirigir con flash=error, se obtuvo %q", rec.Header().Get("Location"))
	}
	overlay, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("fallo leyendo overlay: %v", err)
	}
	if string(overlay) != "estado actual" {
		t.Errorf("un snapshot inválido no debe mutar el overlay: %q", overlay)
	}
}
