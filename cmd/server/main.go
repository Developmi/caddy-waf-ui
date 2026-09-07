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
	// 1. Inicializar las bases: Logger estructurado JSON a stdout (NIST AU-12)
	logs.Setup()

	// 2. Leer configuración de entorno para el puerto de escucha
	// (centralizado en config, hallazgo J5-3)
	bindAddr := config.BindAddr()

	// 3. Ensamblar los grupos de rutas (task 2.7 + rate limiting S4):
	//    - público: login (GET/POST /login) y assets estáticos (/static/:
	//      pico.min.css, app.css, app.js - sin sesión, no contienen datos
	//      sensibles), sin autenticación. El limiter de login (ratelimit.Login)
	//      envuelve el mux público limitando SOLO el POST (RL-1): GET /login
	//      queda libre y la exclusión de RL-3 cae del montaje (/static/,
	//      /health y las páginas SSR nunca se envuelven).
	//    - páginas SSR: GET / (tabs) + mutaciones POST /sites/{domain}/... +
	//      POST /logout, protegidas por sesión (cookie o Bearer, D3) y CSRF
	//      double-submit (D1). El orden Session(CSRF(...)) hace que un
	//      visitante sin sesión sea redirigido a /login antes del chequeo CSRF.
	//    - API RESTful: /api/*, Bearer-pura (sin cambios, Fase 1), con el
	//      limiter ratelimit.API FUERA de auth (D4): las probes sin token
	//      queman presupuesto y el 429 corta antes de auth/CSRF/RequestLogger
	//      (sin Set-Cookie ni inundación de ui_request).
	//    - /health: público sin auth (healthchecks del contenedor).
	//    logs.RequestLogger va DENTRO de auth (solo requests autenticados se
	//    loguean como ui_request, AU-12; /login y el tráfico anónimo nunca) y
	//    FUERA de CSRF (los rechazos CSRF autenticados, 403, también se
	//    registran). /login nunca pasa por RequestLogger.
	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := ratelimit.API(auth.Middleware(logs.RequestLogger(ui.NewRouter())))

	mux := http.NewServeMux()
	mux.Handle("/login", ratelimit.Login(public))
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())

	slog.Info("iniciando Caddy WAF UI", "bind", bindAddr)

	// 4. Levantar el servidor HTTP: la CSP (ui.SecurityHeaders) envuelve el
	// mux completo, así TODAS las respuestas llevan las cabeceras de
	// seguridad. newServer fija los límites del servidor (SH-1).
	srv := newServer(bindAddr, ui.SecurityHeaders(mux))
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("fallo al iniciar el servidor", "error", err)
		os.Exit(1)
	}
}

// newServer construye el *http.Server con los límites de hardening SH-1:
//   - ReadHeaderTimeout 5s: tope para la lectura de headers (mitiga slowloris,
//     G114; se mantiene el valor previo).
//   - WriteTimeout 30s: cubre la cadena admin de Caddy (2 x 10s) con margen.
//   - IdleTimeout 60s: margen sobre el healthcheck del contenedor (30s).
//   - MaxHeaderBytes 1 MiB: tope de tamaño de cabeceras por request.
//
// El helper NO ensambla muxes: recibe el handler ya armado (con
// ui.SecurityHeaders envolviendo el mux) y la dirección de escucha; el
// ensamblado de rutas vive en main().
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
