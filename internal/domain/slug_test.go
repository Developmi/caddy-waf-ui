package domain_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// TestDomainSlug verifies the canonical slug normalization (the tests moved
// with the function from internal/files/naming_test.go, finding J5-5).
func TestDomainSlug(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"Normal domain", "api.example.com", "api_example_com"},
		{"Wildcard domain", "*.example.com", "wildcard_example_com"},
		{"Domain with hyphens", "mi-sitio.com", "mi_sitio_com"},
		{"Uppercase domain", "API.EXAMPLE.COM", "api_example_com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := domain.DomainSlug(tt.domain)
			if result != tt.expected {
				t.Errorf("DomainSlug(%q) = %q; expected %q", tt.domain, result, tt.expected)
			}
		})
	}
}

// TestDomainSlugSanitizesHostileInput: the slug must neutralize EVERY
// character outside [a-zA-Z0-9] (finding J2): slashes, whitespace, control
// chars, "%0A" literal and ".." never survive, even though ValidateDomain
// already filters them upstream (defense in depth). The resulting slug can
// only contain [a-z0-9_] and can never form a path traversal.
func TestDomainSlugSanitizesHostileInput(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Absolute path traversal", "/etc/passwd"},
		{"Relative path traversal", "x/../../tmp/evil"},
		{"Double dot", ".."},
		{"Parent directory traversal", "../.."},
		{"Whitespace", "a b"},
		{"Slash", "a/b"},
		{"Dot slash", "./"},
		{"Control char NUL", "a\x00b"},
		{"Control char tab", "a\tb"},
		{"Newline literal percent-encoded", "foo%0Aabort"},
		{"Quotes", `a"b`},
		{"Braces", "a{b}c"},
		{"Dollar sign", "a$b"},
		{"At sign", "a@b"},
		{"Colon", "a:b"},
		{"Backslash", `a\b`},
		{"Non-ASCII characters", "café.com"},
		{"Underscore", "a_b.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slug := domain.DomainSlug(tt.domain)

			if strings.ContainsAny(slug, `/\`) {
				t.Errorf("DomainSlug(%q) = %q: must not contain path separators", tt.domain, slug)
			}
			if strings.Contains(slug, "..") {
				t.Errorf("DomainSlug(%q) = %q: must not contain consecutive double dots", tt.domain, slug)
			}
			for _, r := range slug {
				valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
				if !valid {
					t.Errorf("DomainSlug(%q) = %q: unsafe character %q", tt.domain, slug, r)
				}
			}
		})
	}
}
