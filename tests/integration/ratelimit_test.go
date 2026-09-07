package integration_test

// Integration tests of the rate limiting (S4, RL-1/RL-2/RL-3/D4).
//
// The mux is assembled here as an EXACT mirror of the assembly of
// cmd/server/main.go after the S4.4 wiring (limiter OUTSIDE auth, D4):
// package main is not importable from integration tests, so this helper
// replicates the mounting order so the RL-3 exclusions (which fall from the
// mounting: /health, /static/, SSR GET and GET /login are never wrapped) are
// verified against the same structure that runs in production. Keep in sync
// with cmd/server/main.go.
//
// The Login/API limiters are process globals (D3: single-process, without
// lifecycle) and are shared between the tests of the package. That is why
// the declaration order matters: the tests that consume login POST budget
// (under-limit and the login-get subtest of exempt) are declared BEFORE the
// global-ceiling test, which drains the shared bucket and runs at the end.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/ratelimit"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

// setupRateLimited assembles the production mux with the rate limiting
// applied: /login wrapped by ratelimit.Login (only POST), /api/* by
// ratelimit.API OUTSIDE auth.Middleware/logs.RequestLogger, and /health,
// /static/ and the SSR pages without any limiter (RL-3 by mounting).
func setupRateLimited(t *testing.T) http.Handler {
	t.Setenv("CADDY_UI_TOKEN", "super-secret-token")

	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := ratelimit.API(auth.Middleware(logs.RequestLogger(ui.NewRouter())))

	mux := http.NewServeMux()
	mux.Handle("/login", ratelimit.Login(public))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())
	return mux
}

// rlRequest fires a request against the mux with an explicit RemoteAddr (the
// limiter key) and returns the recorder.
func rlRequest(t *testing.T, handler http.Handler, method, path, remoteAddr, token string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if method == http.MethodPost {
		form := url.Values{}
		if token != "" {
			form.Set("token", token)
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = remoteAddr
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// assertRetryAfter validates that a 429 response carries an integer
// Retry-After ≥ 1 and that it does NOT set Set-Cookie (the 429 cuts before
// auth/CSRF, D4).
func assertRetryAfter(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	raw := rec.Header().Get("Retry-After")
	retry, err := strconv.Atoi(raw)
	if err != nil || retry < 1 {
		t.Fatalf("Retry-After must be an integer ≥ 1, got %q", raw)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("a limiter 429 must not set Set-Cookie: %q", rec.Header().Get("Set-Cookie"))
	}
	return retry
}

// TestRLLoginUnderLimitThenPerClientBreach (RL-1): with ≤5 POST /login per
// minute the normal PRG flow happens (303 → /, without 429); the sixth POST
// of the same client receives 429 + Retry-After and without Set-Cookie.
func TestRLLoginUnderLimitThenPerClientBreach(t *testing.T) {
	handler := setupRateLimited(t)

	const client = "203.0.113.10:4567"
	for i := 1; i <= 5; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST /login %d/5 under the limit: expected 303, got %d", i, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("POST /login %d/5: expected a redirect to /, got %q", i, loc)
		}
		if rec.Header().Get("Retry-After") != "" {
			t.Errorf("POST /login %d/5 under the limit must not carry Retry-After", i)
		}
	}

	rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
	assertRetryAfter(t, rec)
}

// TestRLAPIBurstToleratedOutsideAuth (RL-2/D4): /api/* allows a burst of 30
// requests per client WITHOUT a token (the limiter runs OUTSIDE auth: the
// anonymous probes burn budget and respond 401, never 429 inside the burst);
// once the burst is exceeded, 429 + Retry-After arrives.
func TestRLAPIBurstToleratedOutsideAuth(t *testing.T) {
	handler := setupRateLimited(t)

	const client = "198.51.100.9:9999"
	for i := 1; i <= 30; i++ {
		rec := rlRequest(t, handler, http.MethodGet, "/api/sites/example.com/backups", client, "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("GET /api %d/30 inside the burst (30): there must be no 429, got 429", i)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api %d/30 without a token: expected 401 (auth outside the limiter), got %d", i, rec.Code)
		}
	}

	blocked := 0
	for i := 31; i <= 70; i++ {
		rec := rlRequest(t, handler, http.MethodGet, "/api/sites/example.com/backups", client, "")
		if rec.Code == http.StatusTooManyRequests {
			assertRetryAfter(t, rec)
			blocked++
			break
		}
	}
	if blocked == 0 {
		t.Error("after exceeding the burst of 30, /api must return 429 at least once")
	}
}

// TestRLExemptRoutesNeverLimited (RL-3): /health, /static/, the SSR pages
// (GET /) and the GET /login page are NOT wrapped by any limiter: a hammer
// far above any threshold never receives 429.
func TestRLExemptRoutesNeverLimited(t *testing.T) {
	handler := setupRateLimited(t)
	const hammer = 65 // far above the global login ceiling (60)

	t.Run("health", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/health", fmt.Sprintf("10.9.0.%d:1", i), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /health %d: expected 200, got %d", i+1, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
				t.Errorf("GET /health %d: unexpected body %q", i+1, rec.Body.String())
			}
		}
	})

	t.Run("static", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/static/app.css", fmt.Sprintf("10.9.1.%d:1", i), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /static/app.css %d: expected 200, got %d", i+1, rec.Code)
			}
		}
	})

	t.Run("ssr-get-pages", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/", fmt.Sprintf("10.9.2.%d:1", i), "")
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("GET / (SSR) %d: the SSR pages are not limited, got 429", i+1)
			}
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
				t.Fatalf("GET / (SSR) %d without a session: expected 302 → /login, got %d %q", i+1, rec.Code, rec.Header().Get("Location"))
			}
		}
	})

	t.Run("login-get-after-post-exhausted", func(t *testing.T) {
		// Same client that already exhausted its POST budget: the GET /login
		// page stays served (the login limiter only applies to POST, D4).
		const client = "203.0.113.99:4567"
		for i := 0; i < 5; i++ {
			rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
		}
		if rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token"); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("setup: the sixth POST must be limited, got %d", rec.Code)
		}
		for i := 0; i < 20; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/login", client, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /login %d with exhausted POST: expected 200, got %d", i+1, rec.Code)
			}
		}
	})
}

// TestRLLoginGlobalCeilingAcrossClients (RL-1): the global ceiling (60/min)
// is a bucket SHARED by all the clients. It runs at the end of the file
// because it drains the process global bucket: first it observes the 429
// (the bucket may come partially consumed by the previous tests, so a clean
// ceiling is not assumed) and then it tests the central property: NEW
// clients, with their full per-client buckets, remain blocked by the
// exhausted global bucket.
func TestRLLoginGlobalCeilingAcrossClients(t *testing.T) {
	handler := setupRateLimited(t)

	// Consume with fresh clients until observing the first 429. The refill
	// is 1 token/s: these attempts run in milliseconds, so the bucket does
	// not recover ≥1 token during the loop (bounded to 70 attempts ≤ 61
	// needed + margin).
	exhausted := false
	for i := 0; i < 70; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", fmt.Sprintf("10.1.0.%d:1234", i), "super-secret-token")
		if rec.Code == http.StatusTooManyRequests {
			assertRetryAfter(t, rec)
			exhausted = true
			break
		}
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST %d of fresh clients under the ceiling: expected 303, got %d", i+1, rec.Code)
		}
	}
	if !exhausted {
		t.Fatal("the global ceiling must be exhausted in ≤70 attempts of fresh clients")
	}

	// Test of the SHARED ceiling: each new client has its full per-client
	// bucket (5/5); if it receives 429 it is because the exhausted GLOBAL
	// bucket blocks it (negligible refill between consecutive requests).
	for i := 0; i < 5; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", fmt.Sprintf("10.2.0.%d:1234", i), "super-secret-token")
		assertRetryAfter(t, rec)
	}
}
