package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot resuelve la raíz del repo desde el directorio del paquete de
// tests (go test ejecuta con cwd = tests/integration).
func repoRoot() string {
	return filepath.Join("..", "..")
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), rel))
	if err != nil {
		t.Fatalf("fallo leyendo %s: %v", rel, err)
	}
	return data
}

// caddyfileExists reporta si el Caddyfile local existe. Está gitignored por
// diseño (el repositorio trackea solo Caddyfile.example), así que en un clone
// fresco no existe y los tests deben degradar al ejemplo canónico.
func caddyfileExists() bool {
	_, err := os.Stat(filepath.Join(repoRoot(), "Caddyfile"))
	return err == nil
}

// readCaddyfile devuelve el Caddyfile de referencia: el local si existe, o el
// ejemplo canónico (Caddyfile.example) en su ausencia. Ambos deben ser
// byte-idénticos (D6), verificado cuando el local está presente.
func readCaddyfile(t *testing.T) []byte {
	t.Helper()
	if caddyfileExists() {
		return readRepoFile(t, "Caddyfile")
	}
	return readRepoFile(t, "Caddyfile.example")
}

// siteBlock devuelve el texto del bloque de sitio que abre con siteLine
// (p.ej. "api.example.com {"), hasta su `}` de cierre a columna 0.
func siteBlock(t *testing.T, content, siteLine string) string {
	t.Helper()
	lines := strings.Split(content, "\n")
	start := -1
	for i, l := range lines {
		if l == siteLine {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatalf("bloque %q no encontrado en el Caddyfile", siteLine)
	}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatalf("bloque %q sin cierre a columna 0", siteLine)
	return ""
}

// TestCaddyfileMatchesExampleByteIdentical: los dos Caddyfiles deben ser
// byte-idénticos (D6) - el ejemplo es autocontenido (los usuarios lo copian)
// y la sincronía está enforced por este test, no por convención.
func TestCaddyfileMatchesExampleByteIdentical(t *testing.T) {
	if !caddyfileExists() {
		t.Skip("Caddyfile no presente (gitignored): Caddyfile.example es el canónico (D6)")
	}

	caddyfile := readRepoFile(t, "Caddyfile")
	example := readRepoFile(t, "Caddyfile.example")

	if !bytes.Equal(caddyfile, example) {
		cl, el := strings.Split(string(caddyfile), "\n"), strings.Split(string(example), "\n")
		diffLine := len(cl) + 1
		for i := 0; i < len(cl) && i < len(el); i++ {
			if cl[i] != el[i] {
				diffLine = i + 1
				break
			}
		}
		t.Errorf("Caddyfile y Caddyfile.example no son byte-idénticos (D6)\n"+
			"Caddyfile: %d bytes / %d líneas | example: %d bytes / %d líneas | primera diferencia línea %d",
			len(caddyfile), len(cl), len(example), len(el), diffLine)
	}
}

// TestCaddyfileManagedBlocksImportPerSlug: los bloques gestionados por la UI
// (api, app) importan los overlays per-slug en orden ip-rules → waf y NO usan
// `import waf` - un segundo coraza_waf inline rompería el reload (R2, D2).
func TestCaddyfileManagedBlocksImportPerSlug(t *testing.T) {
	content := string(readCaddyfile(t))

	managed := []struct {
		site string
		slug string
	}{
		{"api.example.com {", "api_example_com"},
		{"app.example.com {", "app_example_com"},
	}

	for _, m := range managed {
		block := siteBlock(t, content, m.site)

		ipImport := "import /etc/caddy/ui-managed/ip-rules-" + m.slug + ".conf"
		wafImport := "import /etc/caddy/ui-managed/waf-" + m.slug + ".conf"

		if !strings.Contains(block, ipImport) {
			t.Errorf("%s: falta el import per-slug de ip-rules: %s\nbloque:\n%s", m.site, ipImport, block)
		}
		if !strings.Contains(block, wafImport) {
			t.Errorf("%s: falta el import per-slug de waf: %s\nbloque:\n%s", m.site, wafImport, block)
		}
		if strings.Index(block, ipImport) > strings.Index(block, wafImport) {
			t.Errorf("%s: el import de ip-rules debe preceder al de waf (D2)", m.site)
		}
		if strings.Contains(block, "import waf") {
			t.Errorf("%s: bloque gestionado no debe usar `import waf` (doble coraza_waf)", m.site)
		}
	}
}

// TestCaddyfileUnmanagedBlocksKeepSnippetImport: los bloques NO gestionados
// (example.com, assets, ws) conservan `import waf` y no referencian el
// directorio ui-managed (D1, S5).
func TestCaddyfileUnmanagedBlocksKeepSnippetImport(t *testing.T) {
	content := string(readCaddyfile(t))

	for _, site := range []string{"example.com, www.example.com {", "assets.example.com {", "ws.example.com {"} {
		block := siteBlock(t, content, site)

		if !strings.Contains(block, "import waf") {
			t.Errorf("%s: bloque no gestionado debe usar `import waf` (D1)", site)
		}
		if strings.Contains(block, "ui-managed") {
			t.Errorf("%s: bloque no gestionado no debe referenciar /etc/caddy/ui-managed", site)
		}
	}
}

// TestCaddyfileImportCountsMatchContract: conteos globales del contrato R2 -
// exactamente 4 imports ui-managed (api+app × ip-rules+waf) y exactamente 3
// usos de `import waf` (solo los bloques no gestionados).
func TestCaddyfileImportCountsMatchContract(t *testing.T) {
	content := string(readCaddyfile(t))

	// Conteo por línea (no substring): el texto de comentarios que mencione
	// "import waf" o "ui-managed" no debe contaminar el conteo del contrato.
	uiManaged := 0
	snippetImports := 0
	for _, l := range strings.Split(content, "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(l), "import /etc/caddy/ui-managed/"):
			uiManaged++
		case strings.TrimSpace(l) == "import waf":
			snippetImports++
		}
	}

	if uiManaged != 4 {
		t.Errorf("se esperaban 4 imports ui-managed (api+app × ip-rules+waf), hay %d", uiManaged)
	}
	if snippetImports != 3 {
		t.Errorf("se esperaban 3 usos de `import waf` (example.com, assets, ws), hay %d", snippetImports)
	}
}
