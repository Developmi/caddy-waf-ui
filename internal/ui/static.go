package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var staticFS embed.FS

// securityPolicy es la Content-Security-Policy aplicada a todas las
// respuestas por el middleware SecurityHeaders. Los assets son
// autohospedados (go:embed bajo /static, sin CDN) y los handlers viven en
// app.js: no hay scripts ni estilos inline, por eso script-src/style-src
// quedan en 'self'.
const securityPolicy = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// StaticHandler sirve los assets estáticos de la UI (pico.min.css v2.1.1,
// app.css, app.js) desde el binario embebido. Es un recurso PÚBLICO (sin
// sesión): solo archivos estáticos, no contiene datos sensibles. Las rutas
// que terminan en "/" (listados de directorio) responden 404.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(fmt.Sprintf("assets embebidos no disponibles: %v", err))
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// SecurityHeaders envuelve el mux completo y fija las cabeceras de seguridad
// en TODAS las respuestas (páginas SSR, API, login y assets):
//   - Content-Security-Policy: política autohospedada (ver securityPolicy).
//   - X-Content-Type-Options: nosniff - evita que el navegador adivine el
//     tipo MIME de una respuesta y ejecute contenido inyectado como HTML/JS.
//   - Referrer-Policy: no-referrer - las URLs de la UI llevan ?search= y
//     ?domain= (nombres de dominio, términos de búsqueda) y no deben
//     filtrarse a terceros por el header Referer. La UI es una consola de
//     administración sin ningún caso de uso para referrer, por lo que se
//     elige la política más restrictiva.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", securityPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
