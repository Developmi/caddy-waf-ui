package domain_test

import (
	"testing"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/domain"
)

// TestOverlayHeaderRoundTripWAF: Header → ParseHeader debe devolver los mismos
// campos para el formato de 3 segmentos (waf: con modo).
func TestOverlayHeaderRoundTripWAF(t *testing.T) {
	ts := time.Date(2026, 8, 7, 12, 30, 0, 0, time.UTC)
	header := domain.Header("api.example.com", domain.ModeOn, ts)

	want := "# domain: api.example.com | mode: On | updated: 2026-08-07T12:30:00Z"
	if header != want {
		t.Fatalf("Header() = %q; se esperaba %q", header, want)
	}

	info, err := domain.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader falló: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; se esperaba api.example.com", info.Domain)
	}
	if !info.HasMode || info.Mode != domain.ModeOn {
		t.Errorf("Mode = %q (HasMode=%v); se esperaba On", info.Mode, info.HasMode)
	}
	if !info.HasUpdated || !info.Updated.Equal(ts) {
		t.Errorf("Updated = %v (HasUpdated=%v); se esperaba %v", info.Updated, info.HasUpdated, ts)
	}
}

// TestOverlayHeaderRoundTripNoMode: el formato de 2 segmentos (exclusiones e
// ip-rules) round-trip sin modo y sin degradar.
func TestOverlayHeaderRoundTripNoMode(t *testing.T) {
	// RFC3339 no transporta sub-segundos: se usa un timestamp truncado para
	// que el round-trip sea exacto.
	ts := time.Now().UTC().Truncate(time.Second)
	header := domain.Header("api.example.com", "", ts)

	info, err := domain.ParseHeader(header)
	if err != nil {
		t.Fatalf("ParseHeader falló: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; se esperaba api.example.com", info.Domain)
	}
	if info.HasMode || info.Mode != "" {
		t.Errorf("Mode = %q (HasMode=%v); la cabecera sin modo no debe traer modo", info.Mode, info.HasMode)
	}
	if !info.HasUpdated || !info.Updated.Equal(ts) {
		t.Errorf("Updated = %v (HasUpdated=%v); se esperaba %v", info.Updated, info.HasUpdated, ts)
	}
}

// TestParseHeaderTolerant: el parser conserva la tolerancia del scanner
// histórico: espaciado irregular, claves en mayúsculas y segmentos
// desconocidos no rompen el parseo.
func TestParseHeaderTolerant(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantDomain  string
		wantMode    domain.WAFMode
		wantHasMode bool
	}{
		{"Espaciado irregular", "  # domain:  api.example.com  |  mode: Off  |  updated: 2026-08-07T12:30:00Z  ", "api.example.com", domain.ModeOff, true},
		{"Claves en mayusculas", "# domain: api.example.com | MODE: On | UPDATED: 2026-08-07T12:30:00Z", "api.example.com", domain.ModeOn, true},
		{"Segmento desconocido", "# domain: api.example.com | foo: bar | updated: 2026-08-07T12:30:00Z", "api.example.com", "", false},
		{"Sin updated", "# domain: api.example.com | mode: DetectionOnly", "api.example.com", domain.ModeDetectionOnly, true},
		{"Sin modo ni updated", "# domain: api.example.com", "api.example.com", "", false},
		{"Valor vacio en mode", "# domain: api.example.com | mode:", "api.example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := domain.ParseHeader(tt.line)
			if err != nil {
				t.Fatalf("ParseHeader falló: %v", err)
			}
			if info.Domain != tt.wantDomain {
				t.Errorf("Domain = %q; se esperaba %q", info.Domain, tt.wantDomain)
			}
			if info.HasMode != tt.wantHasMode || info.Mode != tt.wantMode {
				t.Errorf("Mode = %q (HasMode=%v); se esperaba %q (HasMode=%v)", info.Mode, info.HasMode, tt.wantMode, tt.wantHasMode)
			}
		})
	}
}

// TestParseHeaderErrors: errores explícitos para cabeceras sin prefijo o sin
// dominio (fail-loud, no silencioso).
func TestParseHeaderErrors(t *testing.T) {
	if _, err := domain.ParseHeader("domain: api.example.com | mode: On"); err == nil {
		t.Error("una línea sin el prefijo '# domain:' debe fallar")
	}
	if _, err := domain.ParseHeader("# domain:   | mode: On"); err == nil {
		t.Error("una cabecera con dominio vacío debe fallar")
	}
}

// TestParseHeaderInvalidTimestamp: un "updated" no parseable no es error de
// cabecera: queda señalado con HasUpdated=false y el valor crudo disponible
// para que el consumidor advierta (mismo comportamiento que el scanner previo).
func TestParseHeaderInvalidTimestamp(t *testing.T) {
	info, err := domain.ParseHeader("# domain: api.example.com | updated: no-es-una-fecha")
	if err != nil {
		t.Fatalf("un timestamp inválido no debe romper la cabecera: %v", err)
	}
	if info.Domain != "api.example.com" {
		t.Errorf("Domain = %q; se esperaba api.example.com", info.Domain)
	}
	if info.HasUpdated {
		t.Error("HasUpdated debe ser false con timestamp inválido")
	}
	if info.UpdatedRaw != "no-es-una-fecha" {
		t.Errorf("UpdatedRaw = %q; se esperaba el valor crudo", info.UpdatedRaw)
	}
}
