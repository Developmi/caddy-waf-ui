package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBearerMiddlewareAcceptsValidToken: with a valid Bearer the middleware
// passes control to the next handler.
func TestBearerMiddlewareAcceptsValidToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/whatever", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("with a valid Bearer it must pass to the next handler, got %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsMissingHeader: missing Authorization header →
// 401 with no body (no information leakage).
func TestBearerMiddlewareRejectsMissingHeader(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing Authorization header: expected 401, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("the 401 must not carry a body: %q", rec.Body.String())
	}
}

// TestBearerMiddlewareRejectsWrongScheme: a non-Bearer scheme (e.g. Basic)
// is rejected with 401.
func TestBearerMiddlewareRejectsWrongScheme(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("non-Bearer scheme: expected 401, got %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsWrongToken: an incorrect token is rejected with
// 401 (constant-time comparison via tokenMatches).
func TestBearerMiddlewareRejectsWrongToken(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token-incorrecto")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", rec.Code)
	}
}

// TestBearerMiddlewareRejectsWhenTokenUnset: with no token configured, no
// value must validate (same semantics as tokenMatches).
func TestBearerMiddlewareRejectsWhenTokenUnset(t *testing.T) {
	t.Setenv("CADDY_UI_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	Middleware(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unconfigured token: expected 401, got %d", rec.Code)
	}
}
