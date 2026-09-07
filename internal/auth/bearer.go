package auth

import "net/http"

// Middleware protects the routes by requiring a valid Bearer token.
// It implements timing-attack protection per the security
// definitions[cite: 1]. Token extraction (bearerToken) and constant-time
// comparison (tokenMatches) live in the shared helpers of session.go, also
// used by Session and CSRF (no drift between them).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Missing, invalid or unconfigured token → 401 with no body (no
		// information leakage)[cite: 1]. tokenMatches covers all three cases.
		if !tokenMatches(bearerToken(r)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// If the token is valid, pass control to the next handler
		next.ServeHTTP(w, r)
	})
}
