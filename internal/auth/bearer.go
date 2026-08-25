package auth

import "net/http"

// Middleware protege las rutas requiriendo un Bearer token válido.
// Implementa protección contra timing attacks según las definiciones de
// seguridad[cite: 1]. La extracción del token (bearerToken) y la comparación
// en tiempo constante (tokenMatches) viven en los helpers compartidos de
// session.go, usados también por Session y CSRF (sin drift entre ambos).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token ausente, inválido o no configurado → 401 sin cuerpo (no
		// information leakage)[cite: 1]. tokenMatches cubre los tres casos.
		if !tokenMatches(bearerToken(r)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Si el token es válido, pasamos el control al siguiente handler
		next.ServeHTTP(w, r)
	})
}
