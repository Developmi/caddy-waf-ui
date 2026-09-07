package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot resolves the repo root from the directory of the test package
// (go test runs with cwd = tests/integration).
func repoRoot() string {
	return filepath.Join("..", "..")
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(), rel))
	if err != nil {
		t.Fatalf("failed reading %s: %v", rel, err)
	}
	return data
}

// caddyfileExists reports whether the local Caddyfile exists. It is
// gitignored by design (the repository tracks only Caddyfile.example), so in
// a fresh clone it does not exist and the tests must fall back to the
// canonical example.
func caddyfileExists() bool {
	_, err := os.Stat(filepath.Join(repoRoot(), "Caddyfile"))
	return err == nil
}

// readCaddyfile returns the reference Caddyfile: the local one if it exists,
// or the canonical example (Caddyfile.example) in its absence. Both must be
// byte-identical (D6), verified when the local one is present.
func readCaddyfile(t *testing.T) []byte {
	t.Helper()
	if caddyfileExists() {
		return readRepoFile(t, "Caddyfile")
	}
	return readRepoFile(t, "Caddyfile.example")
}

// siteBlock returns the text of the site block that opens with siteLine
// (e.g. "api.example.com {"), up to its closing "}" at column 0.
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
		t.Fatalf("block %q not found in the Caddyfile", siteLine)
	}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatalf("block %q without a close at column 0", siteLine)
	return ""
}

// TestCaddyfileMatchesExampleByteIdentical: both Caddyfiles must be
// byte-identical (D6) - the example is self-contained (users copy it) and
// the sync is enforced by this test, not by convention.
func TestCaddyfileMatchesExampleByteIdentical(t *testing.T) {
	if !caddyfileExists() {
		t.Skip("Caddyfile not present (gitignored): Caddyfile.example is the canonical one (D6)")
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
		t.Errorf("Caddyfile and Caddyfile.example are not byte-identical (D6)\n"+
			"Caddyfile: %d bytes / %d lines | example: %d bytes / %d lines | first difference at line %d",
			len(caddyfile), len(cl), len(example), len(el), diffLine)
	}
}

// TestCaddyfileManagedBlocksImportPerSlug: the blocks managed by the UI
// (api, app) import the per-slug overlays in ip-rules → waf order and do NOT
// use `import waf` - a second inline coraza_waf would break the reload
// (R2, D2).
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
			t.Errorf("%s: the per-slug ip-rules import is missing: %s\nblock:\n%s", m.site, ipImport, block)
		}
		if !strings.Contains(block, wafImport) {
			t.Errorf("%s: the per-slug waf import is missing: %s\nblock:\n%s", m.site, wafImport, block)
		}
		if strings.Index(block, ipImport) > strings.Index(block, wafImport) {
			t.Errorf("%s: the ip-rules import must precede the waf one (D2)", m.site)
		}
		if strings.Contains(block, "import waf") {
			t.Errorf("%s: a managed block must not use `import waf` (double coraza_waf)", m.site)
		}
	}
}

// TestCaddyfileUnmanagedBlocksKeepSnippetImport: the NOT managed blocks
// (example.com, assets, ws) keep `import waf` and do not reference the
// ui-managed directory (D1, S5).
func TestCaddyfileUnmanagedBlocksKeepSnippetImport(t *testing.T) {
	content := string(readCaddyfile(t))

	for _, site := range []string{"example.com, www.example.com {", "assets.example.com {", "ws.example.com {"} {
		block := siteBlock(t, content, site)

		if !strings.Contains(block, "import waf") {
			t.Errorf("%s: an unmanaged block must use `import waf` (D1)", site)
		}
		if strings.Contains(block, "ui-managed") {
			t.Errorf("%s: an unmanaged block must not reference /etc/caddy/ui-managed", site)
		}
	}
}

// TestCaddyfileImportCountsMatchContract: global counts of the R2 contract -
// exactly 4 ui-managed imports (api+app × ip-rules+waf) and exactly 3 uses
// of `import waf` (only the unmanaged blocks).
func TestCaddyfileImportCountsMatchContract(t *testing.T) {
	content := string(readCaddyfile(t))

	// Per-line count (not substring): comment text mentioning "import waf"
	// or "ui-managed" must not pollute the contract count.
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
		t.Errorf("expected 4 ui-managed imports (api+app × ip-rules+waf), got %d", uiManaged)
	}
	if snippetImports != 3 {
		t.Errorf("expected 3 uses of `import waf` (example.com, assets, ws), got %d", snippetImports)
	}
}
