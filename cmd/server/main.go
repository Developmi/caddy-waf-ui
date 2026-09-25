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
	if err := run(func(srv *http.Server) error {
		return srv.ListenAndServe()
	}); err != nil {
		slog.Error("failed to start the server", "error", err)
		os.Exit(1)
	}
}

// run wires configuration, logging, handlers and delegates serving to the provided runner.
func run(serve func(*http.Server) error) error {
	// 1. Initialize the foundations: structured JSON logger to stdout (NIST AU-12)
	logs.Setup()

	// 2. Read the environment configuration for the listening port
	bindAddr := config.BindAddr()

	slog.Info("starting Caddy WAF UI", "bind", bindAddr)
	srv := newServer(bindAddr, buildHandler())
	return serve(srv)
}

// buildHandler configures and returns the application's root HTTP handler
// with all route groups, middlewares, and security headers applied.
func buildHandler() http.Handler {
	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := ratelimit.API(auth.Middleware(logs.RequestLogger(ui.NewRouter())))

	mux := http.NewServeMux()
	mux.Handle("/login", ratelimit.Login(public))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())

	return ui.SecurityHeaders(mux)
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
