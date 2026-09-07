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

// sessionCookieName is the name of the session cookie (decision D3):
// the cookie IS the access token, with no server-side state. The same secret
// protects pages and API.
const sessionCookieName = "CADDY_UI_TOKEN"

// csrfContext is the fixed HMAC context used to derive the CSRF token from
// the secret: the raw secret never travels in the DOM (decision D1).
const csrfContext = "csrf"

// sessionMaxAgeSeconds is the session cookie lifetime: 12h (SC-1).
// With daily token rotation, a captured cookie stays valid until that
// post-rotation window — an accepted tradeoff of the stateless design
// (no server-side expiration).
const sessionMaxAgeSeconds = 43200

// tokenFromEnv returns the configured token (empty if unset).
// Centralized in config (finding J5-3).
func tokenFromEnv() string {
	return config.Token()
}

// tokenMatches compares the provided token against the configured one in
// constant time (same anti-timing pattern as bearer.go). An unconfigured
// token never validates.
func tokenMatches(provided string) bool {
	expected := tokenFromEnv()
	if expected == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// bearerToken extracts the token from an Authorization Bearer header, or "".
func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// HasValidSession reports whether the request carries a valid session:
// a CADDY_UI_TOKEN cookie or a valid Bearer (spec web-ui: "cookie or valid
// Bearer").
func HasValidSession(r *http.Request) bool {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && tokenMatches(cookie.Value) {
		return true
	}
	return tokenMatches(bearerToken(r))
}

// SetSessionCookie sets the session cookie with HttpOnly; Secure;
// SameSite=Strict; Path=/ and Max-Age 12h (decision D3: loopback is a
// secure context, which is why Secure works over plain HTTP; SC-1).
func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   sessionMaxAgeSeconds,
	})
}

// Login validates the credential (constant-time comparison) and, if valid,
// sets the session cookie. Returns true only if the session was established.
func Login(w http.ResponseWriter, provided string) bool {
	if !tokenMatches(provided) {
		return false
	}
	SetSessionCookie(w, tokenFromEnv())
	return true
}

// Logout invalidates the client's session cookie (immediate expiration).
func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0), // already expired
	})
}

// Session protects the SSR pages: it accepts a valid session cookie or
// Bearer; without a session it redirects to /login (302, spec web-ui)
// instead of responding 401, because the expected client is a browser.
func Session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !HasValidSession(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CSRFValue derives the double-submit token: HMAC-SHA256(secret, "csrf") in
// hex (decision D1). The raw secret never appears in the DOM, so an XSS
// cannot exfiltrate it for use against /api.
func CSRFValue() (string, error) {
	secret := tokenFromEnv()
	if secret == "" {
		return "", errors.New("CADDY_UI_TOKEN not configured: cannot derive CSRF token")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(csrfContext))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// CSRF validates the hidden "csrf" field (double-submit) on mutation
// requests with constant-time comparison (crypto/subtle). Bearer-authenticated
// requests are exempt: a browser cannot attach Authorization cross-site
// (decision D1). Safe methods (GET/HEAD/OPTIONS) pass without a token.
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
