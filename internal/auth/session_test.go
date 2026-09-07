package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// okHandler es el handler "siguiente" en las pruebas de middleware.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// cookieSesion recupera la cookie CADDY_UI_TOKEN del recorder.
func cookieSesion(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("no se encontró la cookie %s en la respuesta", sessionCookieName)
	return nil
}

func TestLoginSetsSessionCookieFlags(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	if !Login(rec, "super-secret-token") {
		t.Fatal("login con token válido debe devolver true")
	}

	c := cookieSesion(t, rec)
	if c.Value != "super-secret-token" {
		t.Errorf("la cookie debe transportar el token, se obtuvo %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("la cookie de sesión debe ser HttpOnly")
	}
	if !c.Secure {
		t.Error("la cookie de sesión debe ser Secure (loopback es contexto seguro, D3)")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("la cookie de sesión debe ser SameSite=Strict, se obtuvo %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("la cookie debe tener Path=/, se obtuvo %q", c.Path)
	}
	if c.MaxAge != 43200 {
		t.Errorf("la cookie de sesión debe expirar a las 12h (Max-Age=43200, SC-1), se obtuvo %d", c.MaxAge)
	}
}

func TestLoginRejectsWrongToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	if Login(rec, "token-incorrecto") {
		t.Fatal("login con token inválido debe devolver false")
	}
	if rec.Result().Cookies() != nil && len(rec.Result().Cookies()) > 0 {
		t.Error("no debe fijarse cookie con credencial inválida")
	}
}

func TestLoginRejectsWhenTokenUnset(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	rec := httptest.NewRecorder()
	if Login(rec, "") {
		t.Error("sin token configurado no puede haber login")
	}
	if Login(rec, "super-secret-token") {
		t.Error("sin token configurado ningún valor debe validar")
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	Logout(rec)

	c := cookieSesion(t, rec)
	if c.MaxAge >= 0 && c.Expires.After(time.Now()) {
		t.Errorf("logout debe expirar la cookie, MaxAge=%d Expires=%v", c.MaxAge, c.Expires)
	}
}

func TestSessionAcceptsValidCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "super-secret-token", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("con cookie válida debe pasar al siguiente handler, se obtuvo %d", rec.Code)
	}
}

func TestSessionAcceptsValidBearer(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("con Bearer válido debe pasar al siguiente handler, se obtuvo %d", rec.Code)
	}
}

func TestSessionRedirectsWithoutCredentials(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("sin sesión se esperaba 302, se obtuvo %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("se esperaba Location /login, se obtuvo %q", loc)
	}
}

func TestSessionRejectsWrongCookie(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "token-roto", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	rec := httptest.NewRecorder()
	Session(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("con cookie inválida se esperaba 302, se obtuvo %d", rec.Code)
	}
}

func TestCSRFValidTokenPasses(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	token, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue falló: %v", err)
	}
	form := url.Values{"csrf": {token}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("con token CSRF válido debe pasar, se obtuvo %d", rec.Code)
	}
}

func TestCSRFMissingTokenRejected(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("mode=On"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST sin token CSRF se esperaba 403, se obtuvo %d", rec.Code)
	}
}

func TestCSRFWrongTokenRejected(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	form := url.Values{"csrf": {"token-incorrecto"}}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST con token CSRF inválido se esperaba 403, se obtuvo %d", rec.Code)
	}
}

func TestCSRFAllowsSafeMethods(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/", nil)
		rec := httptest.NewRecorder()
		CSRF(okHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s sin token CSRF debe pasar (método seguro), se obtuvo %d", method, rec.Code)
		}
	}
}

func TestCSRFBearerExempt(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("mode=On"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	CSRF(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST autenticado por Bearer debe estar exento de CSRF, se obtuvo %d", rec.Code)
	}
}

func TestCSRFValueDeterministicAndSecretBound(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "secreto-uno")
	first, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue falló: %v", err)
	}
	second, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue falló: %v", err)
	}
	if first != second {
		t.Error("el token CSRF debe ser determinístico para el mismo secreto")
	}

	t.Setenv("CADDY_UI_TOKEN", "secreto-dos")
	other, err := CSRFValue()
	if err != nil {
		t.Fatalf("CSRFValue falló: %v", err)
	}
	if other == first {
		t.Error("el token CSRF debe cambiar cuando cambia el secreto")
	}
}

func TestCSRFValueRequiresToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	if _, err := CSRFValue(); err == nil {
		t.Error("sin token configurado, CSRFValue debe devolver error")
	}
}
