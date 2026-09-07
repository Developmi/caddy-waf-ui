package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/ratelimit"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

func main() {
	// 1. Initialize the foundations: structured JSON logger to stdout (NIST AU-12)
	logs.Setup()

	// 2. Read the environment configuration for the listening port
	// (centralized in config, finding J5-3)
	bindAddr := config.BindAddr()

	// 3. Assemble the route groups (task 2.7 + rate limiting S4):
	//    - public: login (GET/POST /login) and static assets (/static/:
	//      pico.min.css, app.css, app.js - without session, no sensitive
	//      data), without authentication. The login limiter (ratelimit.Login)
	//      wraps the public mux limiting ONLY the POST (RL-1): GET /login
	//      stays free and the RL-3 exclusion falls from the mounting
	//      (/static/, /health and the SSR pages are never wrapped).
	//    - SSR pages: GET / (tabs) + POST /sites/{domain}/... mutations +
	//      POST /logout, protected by session (cookie or Bearer, D3) and
	//      CSRF double-submit (D1). The Session(CSRF(...)) order makes a
	//      visitor without a session be redirected to /login before the CSRF
	//      check.
	//    - RESTful API: /api/*, Bearer-only (unchanged, Phase 1), with the
	//      ratelimit.API limiter OUTSIDE auth (D4): token-less probes burn
	//      budget and the 429 cuts before auth/CSRF/RequestLogger (no
	//      Set-Cookie nor ui_request flooding).
	//    - /health: public without auth (container healthchecks).
	//    logs.RequestLogger goes INSIDE auth (only authenticated requests are
	//    logged as ui_request, AU-12; /login and anonymous traffic never) and
	//    OUTSIDE CSRF (authenticated CSRF rejections, 403, are also
	//    recorded). /login never passes through RequestLogger.
	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := ratelimit.API(auth.Middleware(logs.RequestLogger(ui.NewRouter())))

	mux := http.NewServeMux()
	mux.Handle("/login", ratelimit.Login(public))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())

	slog.Info("starting Caddy WAF UI", "bind", bindAddr)

	// 4. Start the HTTP server: the CSP (ui.SecurityHeaders) wraps the full
	// mux, so ALL the responses carry the security headers. newServer sets
	// the server limits (SH-1).
	srv := newServer(bindAddr, ui.SecurityHeaders(mux))
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("failed to start the server", "error", err)
		os.Exit(1)
	}
}

// newServer builds the *http.Server with the SH-1 hardening limits:
//   - ReadHeaderTimeout 5s: cap for the header read (mitigates slowloris,
//     G114; the previous value is kept).
//   - WriteTimeout 30s: covers the Caddy admin chain (2 x 10s) with margin.
//   - IdleTimeout 60s: margin over the container healthcheck (30s).
//   - MaxHeaderBytes 1 MiB: size cap of the headers per request.
//
// The helper does NOT assemble muxes: it receives the already assembled
// handler (with ui.SecurityHeaders wrapping the mux) and the listening
// address; the route assembly lives in main().
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
