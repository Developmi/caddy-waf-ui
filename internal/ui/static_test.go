package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStaticHandlerServesAssets: los assets autohospedados (pico.min.css,
// app.css, app.js) deben servirse bajo /static/ sin autenticación y con el
// contenido embebido en el binario. Los listados de directorio responden 404.
func TestStaticHandlerServesAssets(t *testing.T) {
	handler := http.StripPrefix("/static/", StaticHandler())

	for _, asset := range []string{"/static/pico.min.css", "/static/app.css", "/static/app.js"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("%s: se esperaba 200, se obtuvo %d", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: el asset no puede estar vacío", asset)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("el listado de directorio debe responder 404, se obtuvo %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/no-existe.css", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("un asset inexistente debe responder 404, se obtuvo %d", rec.Code)
	}
}

// TestSecurityHeadersAppliesCSP: el middleware debe fijar las cabeceras de
// seguridad en TODAS las respuestas (páginas, API, login y assets), sin
// excepciones: CSP autohospedada, X-Content-Type-Options: nosniff (anti MIME
// sniffing) y Referrer-Policy: no-referrer (las URLs llevan ?search=/?domain=
// y no deben filtrarse a terceros).
func TestSecurityHeadersAppliesCSP(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(inner)

	for _, path := range []string{"/", "/login", "/api/whatever", "/health", "/static/app.css"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		got := rec.Header().Get("Content-Security-Policy")
		if got == "" {
			t.Errorf("%s: la respuesta debe llevar Content-Security-Policy", path)
		}
		if !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "script-src 'self'") {
			t.Errorf("%s: la CSP debe permitir solo orígenes propios, se obtuvo %q", path, got)
		}
		if ct := rec.Header().Get("X-Content-Type-Options"); ct != "nosniff" {
			t.Errorf("%s: se esperaba X-Content-Type-Options: nosniff, se obtuvo %q", path, ct)
		}
		if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
			t.Errorf("%s: se esperaba Referrer-Policy: no-referrer, se obtuvo %q", path, rp)
		}
	}
}
