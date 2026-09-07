package domain

import "strings"

// DomainSlug normalizes a domain name to a filesystem-safe format[cite: 1].
// E.g.: api.example.com  →  api_example_com
// E.g.: *.example.com    →  wildcard_example_com
//
// Besides the legacy mappings (. → _, * → wildcard, - → _), EVERY character
// outside [a-zA-Z0-9] (slashes, whitespace, control chars, %0A literal,
// "..", etc.) is replaced with "_": the slug never contains path separators
// or injectable directives. It is the defense-in-depth layer that accompanies
// service.ValidateDomain (strict validation upstream).
//
// It lives in the domain package (pure-domain boundary, finding J5-5): the
// packages that build paths (files, waf, iprules, ui) consume it via
// domain.DomainSlug.
func DomainSlug(domain string) string {
	legacy := strings.NewReplacer(".", "_", "*", "wildcard", "-", "_")
	slug := legacy.Replace(strings.ToLower(domain))

	var b strings.Builder
	b.Grow(len(slug))
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !ok {
			c = '_'
		}
		b.WriteByte(c)
	}
	return b.String()
}
