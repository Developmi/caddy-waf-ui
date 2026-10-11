package domain_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

func FuzzDomainSlug(f *testing.F) {
	// Seed corpus with representative domains, injections, and edge cases
	f.Add("example.com")
	f.Add("api-v1.prod.io")
	f.Add("*.example.com")
	f.Add("../etc/passwd")
	f.Add("domain.com\x00malicious")
	f.Add("UPPER.case.DOMAIN.com")
	f.Add("   padded.domain.org  ")
	f.Add("special!@#$%^&*()_+{}[]:;\"'<>?,./~`")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		slug := domain.DomainSlug(input)

		// Invariant 1: The slug must NEVER contain path separators ('/' or '\')
		if strings.ContainsAny(slug, "/\\") {
			t.Fatalf("DomainSlug(%q) produced path separator: %q", input, slug)
		}

		// Invariant 2: The slug must NEVER contain directory traversal sequence ("..")
		if strings.Contains(slug, "..") {
			t.Fatalf("DomainSlug(%q) produced traversal: %q", input, slug)
		}

		// Invariant 3: The slug must ONLY contain characters in [a-z0-9_]
		for i := 0; i < len(slug); i++ {
			c := slug[i]
			isAlphanumeric := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
			if !isAlphanumeric {
				t.Fatalf("DomainSlug(%q) contained non-whitelisted character %q at pos %d: %q", input, c, i, slug)
			}
		}
	})
}
