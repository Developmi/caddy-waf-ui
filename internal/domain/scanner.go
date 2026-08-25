package domain

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Scanner se encarga de leer el sistema de archivos para descubrir dominios[cite: 1].
// El registry en memoria fue eliminado (hallazgo J5-6): la abstracción se
// creaba y descartaba por request sin aportar estado compartido; Scan devuelve
// los sitios directamente y la frescura se mantiene por lectura por request
// (decisión D2).
type Scanner struct {
	managedDir string
}

// NewScanner crea una nueva instancia del escáner.
func NewScanner(managedDir string) *Scanner {
	return &Scanner{managedDir: managedDir}
}

// Scan lee el directorio ui-managed y devuelve los sitios encontrados.
// Los sitios se registran con el dominio REAL leído de la cabecera del overlay
// ("# domain: | mode: | updated:", contrato compartido en overlay.go), no con
// el slug derivado del nombre de archivo. Los archivos sin cabecera válida se
// omiten con una advertencia y el scan continúa.
func (s *Scanner) Scan() ([]*Site, error) {
	entries, err := os.ReadDir(s.managedDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Si el directorio no existe, no hay nada que escanear
			return nil, nil
		}
		return nil, err
	}

	sites := make([]*Site, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Buscamos archivos que sigan el patrón waf-{slug}.conf[cite: 1]
		if !strings.HasPrefix(name, "waf-") || !strings.HasSuffix(name, ".conf") {
			continue
		}

		site, err := parseSiteHeader(filepath.Join(s.managedDir, name), name)
		if err != nil {
			slog.Warn("overlay sin cabecera valida, omitido", "archivo", name, "error", err)
			continue
		}

		sites = append(sites, site)
	}

	return sites, nil
}

// parseSiteHeader lee la cabecera "# domain: <dominio> | mode: <modo> |
// updated: <RFC3339>" del archivo de overlay y construye el Site. Devuelve
// error si la cabecera no existe o no aporta un dominio: el archivo se omite
// (skip + warn) pero no aborta el scan.
func parseSiteHeader(path, name string) (*Site, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error leyendo overlay: %w", err)
	}

	var headerLine string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, headerPrefix) {
			headerLine = trimmed
			break
		}
	}
	if headerLine == "" {
		return nil, fmt.Errorf("cabecera '# domain:' no encontrada")
	}

	info, err := ParseHeader(headerLine)
	if err != nil {
		return nil, err
	}

	site := &Site{
		Domain: info.Domain,
		Mode:   ModeDetectionOnly, // Valor por defecto si la cabecera no define modo
	}

	// Modo presente pero desconocido: se mantiene el default no-bloqueante (el
	// skip ocultaría el dominio y rompería forward-compat con modos futuros),
	// pero el flag Degraded advierte que la UI NO refleja el estado real
	// cargado en Caddy (W1 verify).
	if !info.HasMode {
		site.Mode = ModeDetectionOnly
	} else {
		switch info.Mode {
		case ModeOn, ModeOff, ModeDetectionOnly:
			site.Mode = info.Mode
		default:
			site.Degraded = true
			slog.Warn("modo desconocido en cabecera, se usa DetectionOnly (sitio degradado)", "archivo", name, "mode", info.Mode)
		}
	}

	if info.HasUpdated {
		site.Updated = info.Updated
	} else if info.UpdatedRaw != "" {
		slog.Warn("timestamp 'updated' invalido en cabecera", "archivo", name, "updated", info.UpdatedRaw)
	}

	return site, nil
}
