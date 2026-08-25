package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/ui"
)

func main() {
	// 1. Inicializar las bases: Logger estructurado JSON a stdout (NIST AU-12)
	logs.Setup()

	// 2. Leer configuración de entorno para el puerto de escucha
	// (centralizado en config, hallazgo J5-3)
	bindAddr := config.BindAddr()

	// 3. Ensamblar los grupos de rutas (task 2.7):
	//    - público: login (GET/POST /login) y assets estáticos (/static/:
	//      pico.min.css, app.css, app.js - sin sesión, no contienen datos
	//      sensibles), sin autenticación.
	//    - páginas SSR: GET / (tabs) + mutaciones POST /sites/{domain}/... +
	//      POST /logout, protegidas por sesión (cookie o Bearer, D3) y CSRF
	//      double-submit (D1). El orden Session(CSRF(...)) hace que un
	//      visitante sin sesión sea redirigido a /login antes del chequeo CSRF.
	//    - API RESTful: /api/*, Bearer-pura (sin cambios, Fase 1).
	//    - /health: público sin auth (healthchecks del contenedor).
	//    logs.RequestLogger va DENTRO de auth (solo requests autenticados se
	//    loguean como ui_request, AU-12; /login y el tráfico anónimo nunca) y
	//    FUERA de CSRF (los rechazos CSRF autenticados, 403, también se
	//    registran). /login nunca pasa por RequestLogger.
	public := ui.NewLoginMux()
	pages := auth.Session(logs.RequestLogger(auth.CSRF(ui.NewPagesMux())))
	api := auth.Middleware(logs.RequestLogger(ui.NewRouter()))

	mux := http.NewServeMux()
	mux.Handle("/login", public)
	mux.Handle("/static/", http.StripPrefix("/static/", ui.StaticHandler()))
	mux.Handle("/", pages)
	mux.Handle("/api/", api)
	mux.Handle("/health", ui.HealthHandler())

	slog.Info("iniciando Caddy WAF UI", "bind", bindAddr)

	// 4. Levantar el servidor HTTP: la CSP (ui.SecurityHeaders) envuelve el
	// mux completo, así TODAS las respuestas llevan las cabeceras de
	// seguridad. ReadHeaderTimeout fija un tope para la lectura de headers
	// (mitiga slowloris; G114).
	srv := &http.Server{
		Addr:              bindAddr,
		Handler:           ui.SecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("fallo al iniciar el servidor", "error", err)
		os.Exit(1)
	}
}
