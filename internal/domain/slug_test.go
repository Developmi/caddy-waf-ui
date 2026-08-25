package domain_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// TestDomainSlug verifica la normalización canónica del slug (los tests se
// movieron con la función desde internal/files/naming_test.go, hallazgo J5-5).
func TestDomainSlug(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"Dominio normal", "api.example.com", "api_example_com"},
		{"Dominio con comodín", "*.example.com", "wildcard_example_com"},
		{"Dominio con guiones", "mi-sitio.com", "mi_sitio_com"},
		{"Dominio en mayúsculas", "API.EXAMPLE.COM", "api_example_com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := domain.DomainSlug(tt.domain)
			if result != tt.expected {
				t.Errorf("DomainSlug(%q) = %q; se esperaba %q", tt.domain, result, tt.expected)
			}
		})
	}
}

// TestDomainSlugSanitizesHostileInput: el slug debe neutralizar TODO carácter
// fuera de [a-zA-Z0-9] (hallazgo J2): slashes, whitespace, control chars,
// "%0A" literal y ".." jamás sobreviven, aunque ValidateDomain ya los filtre
// aguas arriba (defensa en profundidad). El slug resultante solo puede
// contener [a-z0-9_] y nunca formar path traversal.
func TestDomainSlugSanitizesHostileInput(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Path traversal absoluto", "/etc/passwd"},
		{"Path traversal relativo", "x/../../tmp/evil"},
		{"Doble punto", ".."},
		{"Subida de directorio", "../.."},
		{"Whitespace", "a b"},
		{"Slash", "a/b"},
		{"Punto y barra", "./"},
		{"Control char NUL", "a\x00b"},
		{"Control char tab", "a\tb"},
		{"Newline literal percent-encoded", "foo%0Aabort"},
		{"Comillas", `a"b`},
		{"Llaves", "a{b}c"},
		{"Signo peso", "a$b"},
		{"Arroba", "a@b"},
		{"Dos puntos", "a:b"},
		{"Backslash", `a\b`},
		{"Caracteres no ASCII", "café.com"},
		{"Underscore", "a_b.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slug := domain.DomainSlug(tt.domain)

			if strings.ContainsAny(slug, `/\`) {
				t.Errorf("DomainSlug(%q) = %q: no debe contener separadores de ruta", tt.domain, slug)
			}
			if strings.Contains(slug, "..") {
				t.Errorf("DomainSlug(%q) = %q: no debe contener doble punto consecutivo", tt.domain, slug)
			}
			for _, r := range slug {
				valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
				if !valid {
					t.Errorf("DomainSlug(%q) = %q: carácter no seguro %q", tt.domain, slug, r)
				}
			}
		})
	}
}
