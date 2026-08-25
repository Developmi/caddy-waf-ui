package domain

import "strings"

// DomainSlug normaliza un nombre de dominio a un formato seguro para el
// sistema de archivos[cite: 1].
// Ej: api.example.com  →  api_example_com
// Ej: *.example.com    →  wildcard_example_com
//
// Además de los mapeos legados (. → _, * → wildcard, - → _), TODO carácter
// fuera de [a-zA-Z0-9] (slashes, whitespace, control chars, %0A literal,
// "..", etc.) se reemplaza por "_": el slug jamás contiene separadores de
// ruta ni directivas inyectables. Es la capa de defensa en profundidad que
// acompaña a service.ValidateDomain (validación estricta aguas arriba).
//
// Vive en el paquete domain (frontera pure-domain, hallazgo J5-5): los
// paquetes que construyen rutas (files, waf, iprules, ui) lo consumen vía
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
