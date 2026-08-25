package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBearerMiddlewareAcceptsValidToken: con un Bearer válido el middleware
// pasa el control al siguiente handler.
func TestBearerMiddlewareAcceptsValidToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/whatever", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("con Bearer válido debe pasar al siguiente handler, se obtuvo %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsMissingHeader: sin header Authorization → 401
// sin cuerpo (no information leakage).
func TestBearerMiddlewareRejectsMissingHeader(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("sin header Authorization se esperaba 401, se obtuvo %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("el 401 no debe llevar cuerpo: %q", rec.Body.String())
	}
}

// TestBearerMiddlewareRejectsWrongScheme: un esquema que no es Bearer (p.ej.
// Basic) se rechaza con 401.
func TestBearerMiddlewareRejectsWrongScheme(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("esquema no-Bearer se esperaba 401, se obtuvo %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsWrongToken: un token incorrecto se rechaza con
// 401 (comparación en tiempo constante vía tokenMatches).
func TestBearerMiddlewareRejectsWrongToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token-incorrecto")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("token incorrecto se esperaba 401, se obtuvo %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsWhenTokenUnset: sin token configurado ningún
// valor debe validar (misma semántica que tokenMatches).
func TestBearerMiddlewareRejectsWhenTokenUnset(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("sin token configurado se esperaba 401, se obtuvo %d", rec.Code)
	}
}
