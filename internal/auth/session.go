package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// sessionCookieName es el nombre de la cookie de sesión (decisión D3):
// la cookie ES el token de acceso, sin estado en servidor. El mismo secreto
// protege páginas y API.
const sessionCookieName = "CADDY_UI_TOKEN"

// csrfContext es la clave fija del HMAC que deriva el token CSRF a partir
// del secreto: el secreto crudo nunca viaja en el DOM (decisión D1).
const csrfContext = "csrf"

// tokenFromEnv devuelve el token configurado (vacío si no está definido).
// Centralizado en config (hallazgo J5-3).
func tokenFromEnv() string {
	return config.Token()
}

// tokenMatches compara en tiempo constante el token provisto contra el
// configurado (mismo patrón anti-timing que bearer.go). Un token no
// configurado nunca valida.
func tokenMatches(provided string) bool {
	expected := tokenFromEnv()
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// bearerToken extrae el token de un header Authorization Bearer, o "".
func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// HasValidSession indica si el request trae una sesión válida: cookie
// CADDY_UI_TOKEN o Bearer válido (spec web-ui: "cookie or valid Bearer").
func HasValidSession(r *http.Request) bool {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && tokenMatches(cookie.Value) {
		return true
	}
	return tokenMatches(bearerToken(r))
}

// SetSessionCookie fija la cookie de sesión con HttpOnly; Secure;
// SameSite=Strict y Path=/ (decisión D3: loopback es un contexto seguro, por
// eso Secure funciona sobre HTTP plano).
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// Login valida la credencial (comparación en tiempo constante) y, si es
// válida, fija la cookie de sesión. Devuelve true solo si la sesión quedó
// establecida.
func Login(w http.ResponseWriter, provided string) bool {
	if !tokenMatches(provided) {
		return false
	}
	SetSessionCookie(w, tokenFromEnv())
	return true
}

// Logout invalida la cookie de sesión del cliente (expiración inmediata).
func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0), // ya vencida
	})
}

// Session protege las páginas SSR: acepta cookie de sesión o Bearer válido;
// sin sesión redirige a /login (302, spec web-ui) en lugar de responder 401,
// porque el cliente esperado es un navegador.
func Session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !HasValidSession(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CSRFValue deriva el token de doble envío: HMAC-SHA256(secreto, "csrf") en
// hex (decisión D1). El secreto crudo nunca aparece en el DOM, así un XSS no
// puede exfiltrarlo para su uso contra /api.
func CSRFValue() (string, error) {
	secret := tokenFromEnv()
	if secret == "" {
		return "", errors.New("CADDY_UI_TOKEN no configurado: no se puede derivar token CSRF")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(csrfContext))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CSRF valida el campo oculto "csrf" (double-submit) en los requests de
// mutación, con comparación en tiempo constante (crypto/subtle). Los
// requests autenticados por Bearer quedan exentos: un navegador no puede
// adjuntar Authorization cross-site (decisión D1). Los métodos seguros
// (GET/HEAD/OPTIONS) pasan sin token.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if tokenMatches(bearerToken(r)) {
			next.ServeHTTP(w, r)
			return
		}
		expected, err := CSRFValue()
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		provided := r.FormValue("csrf")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
