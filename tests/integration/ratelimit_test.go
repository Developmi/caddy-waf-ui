package integration_test

// Tests de integración del rate limiting (S4, RL-1/RL-2/RL-3/D4).
//
// El mux se ensambla aquí como espejo EXACTO del ensamblado de
// cmd/server/main.go tras el wiring de S4.4 (limiter FUERA de auth, D4):
// package main no es importable desde tests de integración, así que este
// helper replica el orden de montaje para que las exclusiones de RL-3 (que
// caen del montaje: /health, /static/, SSR GET y GET /login nunca se envuelven)
// queden verificadas contra la misma estructura que corre en producción.
// Mantener en sync con cmd/server/main.go.
//
// Los limitadores de Login/API son globales de proceso (D3: single-process,
// sin lifecycle) y se sharen entre los tests del paquete. Por eso el orden
// de declaración importa: los tests que consumen presupuesto de login POST
// (under-limit y el subtest login-get de exempt) se declaran ANTES del test
// del techo global, que drena el bucket compartido y corre al final.

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

// setupRateLimited ensambla el mux de producción con el rate limiting
// aplicado: /login envuelto por ratelimit.Login (solo POST), /api/* por
// ratelimit.API FUERA de auth.Middleware/logs.RequestLogger, y /health,
// /static/ y las páginas SSR sin ningún limiter (RL-3 por montaje).
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

// rlRequest dispara un request contra el mux con RemoteAddr explícito (la
// clave del limiter) y devuelve el recorder.
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

// assertRetryAfter valida que una respuesta 429 lleve Retry-After entero ≥ 1
// y que NO fije Set-Cookie (el 429 corta antes de auth/CSRF, D4).
func assertRetryAfter(t *testing.T, rec *httptest.ResponseRecorder) int {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("se esperaba 429, se obtuvo %d", rec.Code)
	}
	raw := rec.Header().Get("Retry-After")
	retry, err := strconv.Atoi(raw)
	if err != nil || retry < 1 {
		t.Fatalf("Retry-After debe ser un entero ≥ 1, se obtuvo %q", raw)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("un 429 del limiter no debe fijar Set-Cookie: %q", rec.Header().Get("Set-Cookie"))
	}
	return retry
}

// TestRLLoginUnderLimitThenPerClientBreach (RL-1): con ≤5 POST /login por
// minuto el flujo PRG normal ocurre (303 → /, sin 429); el sexto POST del
// mismo cliente recibe 429 + Retry-After y sin Set-Cookie.
func TestRLLoginUnderLimitThenPerClientBreach(t *testing.T) {
	handler := setupRateLimited(t)

	const client = "203.0.113.10:4567"
	for i := 1; i <= 5; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST /login %d/5 bajo el límite: se esperaba 303, se obtuvo %d", i, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("POST /login %d/5: se esperaba redirección a /, se obtuvo %q", i, loc)
		}
		if rec.Header().Get("Retry-After") != "" {
			t.Errorf("POST /login %d/5 bajo el límite no debe llevar Retry-After", i)
		}
	}

	rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
	assertRetryAfter(t, rec)
}

// TestRLAPIBurstToleratedOutsideAuth (RL-2/D4): /api/* admite una ráfaga de
// 30 requests por cliente SIN token (el limiter corre FUERA de auth: las
// probes anónimas queman presupuesto y responden 401, nunca 429 dentro del
// burst); superado el burst, llega 429 + Retry-After.
func TestRLAPIBurstToleratedOutsideAuth(t *testing.T) {
	handler := setupRateLimited(t)

	const client = "198.51.100.9:9999"
	for i := 1; i <= 30; i++ {
		rec := rlRequest(t, handler, http.MethodGet, "/api/sites/example.com/backups", client, "")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("GET /api %d/30 dentro del burst (30): no debe haber 429, se obtuvo 429", i)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api %d/30 sin token: se esperaba 401 (auth por fuera del limiter), se obtuvo %d", i, rec.Code)
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
		t.Error("superado el burst de 30, /api debe devolver 429 al menos una vez")
	}
}

// TestRLExemptRoutesNeverLimited (RL-3): /health, /static/, las páginas SSR
// (GET /) y la página GET /login NO están envueltas por ningún limiter: un
// martilleo muy por encima de cualquier umbral jamás recibe 429.
func TestRLExemptRoutesNeverLimited(t *testing.T) {
	handler := setupRateLimited(t)
	const hammer = 65 // muy por encima del techo global de login (60)

	t.Run("health", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/health", fmt.Sprintf("10.9.0.%d:1", i), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /health %d: se esperaba 200, se obtuvo %d", i+1, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
				t.Errorf("GET /health %d: cuerpo inesperado %q", i+1, rec.Body.String())
			}
		}
	})

	t.Run("static", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/static/app.css", fmt.Sprintf("10.9.1.%d:1", i), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /static/app.css %d: se esperaba 200, se obtuvo %d", i+1, rec.Code)
			}
		}
	})

	t.Run("ssr-get-pages", func(t *testing.T) {
		for i := 0; i < hammer; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/", fmt.Sprintf("10.9.2.%d:1", i), "")
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("GET / (SSR) %d: las páginas SSR no se limitan, se obtuvo 429", i+1)
			}
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
				t.Fatalf("GET / (SSR) %d sin sesión: se esperaba 302 → /login, se obtuvo %d %q", i+1, rec.Code, rec.Header().Get("Location"))
			}
		}
	})

	t.Run("login-get-after-post-exhausted", func(t *testing.T) {
		// Mismo cliente que ya agotó su presupuesto de POST: la página GET
		// /login sigue servida (el limiter de login solo aplica a POST, D4).
		const client = "203.0.113.99:4567"
		for i := 0; i < 5; i++ {
			rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token")
		}
		if rec := rlRequest(t, handler, http.MethodPost, "/login", client, "super-secret-token"); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("setup: el sexto POST debe estar limitado, se obtuvo %d", rec.Code)
		}
		for i := 0; i < 20; i++ {
			rec := rlRequest(t, handler, http.MethodGet, "/login", client, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /login %d con POST agotado: se esperaba 200, se obtuvo %d", i+1, rec.Code)
			}
		}
	})
}

// TestRLLoginGlobalCeilingAcrossClients (RL-1): el techo global (60/min) es
// un bucket COMPARTIDO por todos los clients. Corre al final del archivo
// porque drena el bucket global del proceso: primero observa el 429 (el
// bucket puede venir parcialmente consumido por los tests previos, así que no
// se assume un techo limpio) y luego prueba la propiedad central: clients
// NUEVOS, con sus buckets por-cliente llenos, siguen bloqueados por el bucket
// global agotado.
func TestRLLoginGlobalCeilingAcrossClients(t *testing.T) {
	handler := setupRateLimited(t)

	// Consumir con clients frescos hasta observar el primer 429. El refill
	// es 1 token/s: estos intentos corren en milisegundos, así que el bucket
	// no recupera ≥1 token durante el loop (acotado a 70 intentos ≤ 61
	// necesarios + margen).
	exhausted := false
	for i := 0; i < 70; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", fmt.Sprintf("10.1.0.%d:1234", i), "super-secret-token")
		if rec.Code == http.StatusTooManyRequests {
			assertRetryAfter(t, rec)
			exhausted = true
			break
		}
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST %d de clients frescos bajo el techo: se esperaba 303, se obtuvo %d", i+1, rec.Code)
		}
	}
	if !exhausted {
		t.Fatal("el techo global debe agotarse en ≤70 intentos de clients frescos")
	}

	// Prueba del techo COMPARTIDO: cada cliente nuevo tiene su bucket
	// por-cliente lleno (5/5); si recibe 429 es porque el bucket GLOBAL
	// agotado lo bloquea (refill despreciable entre requests consecutivos).
	for i := 0; i < 5; i++ {
		rec := rlRequest(t, handler, http.MethodPost, "/login", fmt.Sprintf("10.2.0.%d:1234", i), "super-secret-token")
		assertRetryAfter(t, rec)
	}
}
