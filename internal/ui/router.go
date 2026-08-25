package ui

import (
	"net/http"
)

// NewRouter ensambla las rutas RESTful de la API de gestión.
// Los path params (Go 1.22+ ServeMux) reemplazan a los endpoints planos:
// el contrato viejo (/api/mode, /api/exclusions, /api/iprules) ya no existe
// y devuelve 404 naturalmente. /health NO vive aquí: main.go lo monta aparte
// (fuera del mux autenticado) para los healthchecks del contenedor.
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// Endpoints RESTful de configuración de WAF y Seguridad
	mux.HandleFunc("PUT /api/sites/{domain}/mode", HandleSetMode)
	mux.HandleFunc("PUT /api/sites/{domain}/exclusions", HandleSetExclusions)
	mux.HandleFunc("PUT /api/sites/{domain}/iprules", HandleSetIPRules)

	// Endpoints RESTful de snapshots y rollback (spec backup-recovery)
	mux.HandleFunc("GET /api/sites/{domain}/backups", HandleListBackups)
	mux.HandleFunc("POST /api/sites/{domain}/rollback", HandleRollback)

	return mux
}

// HealthHandler devuelve el endpoint de estado público. Se monta por
// separado en main.go, FUERA del middleware de auth, para que los
// healthchecks del contenedor no necesiten credenciales.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}
