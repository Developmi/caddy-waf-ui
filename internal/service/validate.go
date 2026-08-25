package service

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidDomain señala un nombre de dominio que no cumple el formato de
// hostname estricto (hallazgo J2: inyección de directivas Caddyfile y path
// traversal de backups). Los handlers REST lo traducen a 400 Bad Request,
// mismo patrón sentinel que ErrInvalidMode y files.ErrInvalidBackup.
var ErrInvalidDomain = errors.New("dominio inválido")

// maxDomainLength es el límite superior de un hostname/FQDN sin el punto
// final (RFC 1035: 255 bytes con separadores → 253 caracteres de labels).
const maxDomainLength = 253

// maxLabelLength es el límite por label de un hostname (RFC 1035).
const maxLabelLength = 63

// ValidateDomain valida un dominio como hostname/FQDN estricto: solo
// [a-zA-Z0-9.-], sin doble punto consecutivo, sin puntos al inicio/final, y
// con cada label cumpliendo [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])? (1..63
// caracteres, alfanuméricos o guiones, sin empezar ni terminar con guion).
// Rechaza todo lo demás (slashes, whitespace, control chars, %0A, comillas,
// llaves, $, @, "..", etc.) con un error descriptivo en español.
//
// Es la defensa PRINCIPAL contra la inyección de directivas en la cabecera
// "# domain:" de los overlays y contra el path traversal de backups: se
// invoca en las entradas públicas de la cadena (UpdateWAFMode,
// UpdateExclusions, UpdateIPRules, Rollback) ANTES de cualquier uso del
// dominio en rutas, plantillas o backups. DomainSlug (internal/domain/slug.go)
// queda como capa adicional de saneamiento (defensa en profundidad).
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("%w: el dominio está vacío", ErrInvalidDomain)
	}
	if len(domain) > maxDomainLength {
		return fmt.Errorf("%w: %q supera el máximo de %d caracteres", ErrInvalidDomain, domain, maxDomainLength)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("%w: %q no puede empezar ni terminar con un punto", ErrInvalidDomain, domain)
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("%w: %q contiene doble punto consecutivo", ErrInvalidDomain, domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("%w: %q: %v", ErrInvalidDomain, domain, err)
		}
	}
	return nil
}

// validateLabel verifica un label individual de hostname: 1..63 caracteres,
// solo alfanuméricos y guiones, sin guiones al inicio ni al final. Devuelve
// el detalle sin el sentinel (ValidateDomain lo envuelve con contexto).
func validateLabel(label string) error {
	if len(label) == 0 || len(label) > maxLabelLength {
		return fmt.Errorf("longitud de label fuera de rango (1..%d)", maxLabelLength)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("los labels no pueden empezar ni terminar con guion")
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("caracter %q no permitido (solo [a-zA-Z0-9.-])", c)
		}
	}
	return nil
}
