package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStaticHandlerServesAssets: the self-hosted assets (pico.min.css,
// app.css, app.js) must be served under /static/ without authentication and
// with the content embedded in the binary. Directory listings respond 404.
func TestStaticHandlerServesAssets(t *testing.T) {
	handler := http.StripPrefix("/static/", StaticHandler())

	for _, asset := range []string{"/static/pico.min.css", "/static/app.css", "/static/app.js"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, asset, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: the asset cannot be empty", asset)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("the directory listing must respond 404, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/no-such-file.css", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a nonexistent asset must respond 404, got %d", rec.Code)
	}
}

// TestSecurityHeadersAppliesCSP: the middleware must set the security headers
// on ALL the responses (pages, API, login and assets), without exceptions:
// self-hosted CSP, X-Content-Type-Options: nosniff (anti MIME sniffing) and
// Referrer-Policy: no-referrer (the URLs carry ?search=/?domain= and must not
// leak to third parties).
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
			t.Errorf("%s: the response must carry Content-Security-Policy", path)
		}
		if !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "script-src 'self'") {
			t.Errorf("%s: the CSP must allow only same-origin sources, got %q", path, got)
		}
		if ct := rec.Header().Get("X-Content-Type-Options"); ct != "nosniff" {
			t.Errorf("%s: expected X-Content-Type-Options: nosniff, got %q", path, ct)
		}
		if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
			t.Errorf("%s: expected Referrer-Policy: no-referrer, got %q", path, rp)
		}
	}
}

// TestSecurityHeadersHSTS (SH-2): Strict-Transport-Security must be emitted
// ONLY when X-Forwarded-Proto is "https" (case-insensitive comparison: Caddy
// adds it as "https" in reverse_proxy when the original request entered over
// TLS). The value must be exactly "max-age=31536000" (1 year, OWASP):
// without includeSubDomains nor preload (no-goals of the change). Without
// XFP or with a proto other than https, the header must be absent (RFC 6797:
// it is inert over plain HTTP).
func TestSecurityHeadersHSTS(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(inner)

	tests := []struct {
		name string
		xfp  string // value of X-Forwarded-Proto; "" = header absent
		want string // expected value of Strict-Transport-Security; "" = absent
	}{
		{"proxy https", "https", "max-age=31536000"},
		{"proxy HTTPS mayusculas", "HTTPS", "max-age=31536000"},
		{"sin X-Forwarded-Proto", "", ""},
		{"proxy http", "http", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			got := rec.Header().Get("Strict-Transport-Security")
			if tt.want == "" {
				if got != "" {
					t.Errorf("X-Forwarded-Proto %q: expected no Strict-Transport-Security, got %q", tt.xfp, got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("X-Forwarded-Proto %q: expected exact Strict-Transport-Security %q, got %q", tt.xfp, tt.want, got)
			}
		})
	}
}
