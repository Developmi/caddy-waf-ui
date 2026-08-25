package domain

import (
	"fmt"
	"strings"
	"time"
)

// Contrato compartido de la cabecera de los overlays (hallazgo J5-4): el
// formato "# domain: | mode: | updated:" vivía como literales en los 3
// writers (waf, exclusions, ip-rules) y se re-parseaba a mano en el scanner.
// Header/ParseHeader son el único lugar que conoce el formato; los writers
// generan y el scanner consume, con round-trip exacto (ver overlay_test.go).
//
// La cabecera es un contrato de archivo en disco: su forma NO puede cambiar
// (backwards compat con los overlays existentes).

// headerPrefix es el prefijo que identifica la cabecera dentro del overlay.
const headerPrefix = "# domain:"

// OverlayHeader describe los campos que transporta la cabecera de un overlay.
// Mode conserva el valor CRUDO ("" si la cabecera no trae modo): interpretar
// la validez del modo es decisión del consumidor (el scanner marca el sitio
// como degradado ante un modo desconocido, W1).
type OverlayHeader struct {
	Domain     string
	Mode       WAFMode
	Updated    time.Time
	HasMode    bool
	HasUpdated bool
	// UpdatedRaw es el valor crudo de "updated" (para que el consumidor
	// pueda advertir con el valor real si el timestamp no parsea).
	UpdatedRaw string
}

// Header construye la línea de cabecera de un overlay. Con mode no vacío
// emite el formato de 3 segmentos (waf); sin modo, el de 2 (exclusiones e
// ip-rules). El timestamp siempre se normaliza a UTC RFC3339: ese es el
// formato que parsea ParseHeader y que muestra la UI.
func Header(domain string, mode WAFMode, updated time.Time) string {
	ts := updated.UTC().Format(time.RFC3339)
	if mode == "" {
		return fmt.Sprintf("%s %s | updated: %s", headerPrefix, domain, ts)
	}
	return fmt.Sprintf("%s %s | mode: %s | updated: %s", headerPrefix, domain, mode, ts)
}

// ParseHeader extrae los campos de una línea de cabecera de overlay generada
// por Header(). Es tolerante con el espaciado y las mayúsculas de las claves
// (mismo comportamiento que el parser histórico del scanner): los segmentos
// desconocidos se ignoran, un "updated" no parseable queda señalado con
// HasUpdated=false y un dominio vacío es un error.
func ParseHeader(line string) (OverlayHeader, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, headerPrefix) {
		return OverlayHeader{}, fmt.Errorf("cabecera %q no encontrada", headerPrefix)
	}

	// Primer segmento: el dominio. Segmentos siguientes: pares clave: valor.
	rest := strings.TrimSpace(strings.TrimPrefix(line, headerPrefix))
	domainPart, remaining, _ := strings.Cut(rest, "|")

	h := OverlayHeader{Domain: strings.TrimSpace(domainPart)}
	if h.Domain == "" {
		return OverlayHeader{}, fmt.Errorf("cabecera sin dominio")
	}

	for _, part := range strings.Split(remaining, "|") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "mode":
			h.Mode = WAFMode(strings.TrimSpace(value))
			h.HasMode = true
		case "updated":
			raw := strings.TrimSpace(value)
			h.UpdatedRaw = raw
			if ts, err := time.Parse(time.RFC3339, raw); err == nil {
				h.Updated = ts
				h.HasUpdated = true
			}
		}
	}

	return h, nil
}
