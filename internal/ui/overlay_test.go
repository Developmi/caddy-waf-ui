package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Los parsers leen EXCLUSIVAMENTE el formato que genera este proyecto
// (waf/exclusions.go e iprules/rules.go): el round-trip debe ser exacto.

func TestParseExclusionsOverlayURLLevelAndTargeted(t *testing.T) {
	content := []byte(`# Caddy WAF UI managed - do not edit manually
# domain: example.com | updated: 2026-08-07T12:00:00Z

SecRuleRemoveById 942100
SecRule ARGS:q "@unconditionalMatch" "id:9000001,phase:2,pass,nolog,ctl:ruleRemoveById=942100"
SecRuleRemoveByTag "php-code-injection"
SecRule ARGS:cmd "@unconditionalMatch" "id:9000002,phase:2,pass,nolog,ctl:ruleRemoveByTag=rce"
# comentario suelto que debe ignorarse
`)

	got, err := parseExclusionsOverlay(content)
	if err != nil {
		t.Fatalf("parse falló: %v", err)
	}
	want := []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "942100"},
		{Type: waf.ExcludeByID, Value: "942100", Param: "q"},
		{Type: waf.ExcludeByTag, Value: "php-code-injection"},
		{Type: waf.ExcludeByTag, Value: "rce", Param: "cmd"},
	}
	if len(got) != len(want) {
		t.Fatalf("se esperaban %d exclusiones, se obtuvieron %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entrada %d: se esperaba %+v, se obtuvo %+v", i, want[i], got[i])
		}
	}
}

func TestParseExclusionsOverlayEmpty(t *testing.T) {
	got, err := parseExclusionsOverlay([]byte("# No exclusions configured for this domain.\n"))
	if err != nil {
		t.Fatalf("parse falló: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("sin reglas el parse debe devolver lista vacía, se obtuvo %+v", got)
	}
}

func TestParseIPRulesOverlayDenyAndAllow(t *testing.T) {
	content := []byte(`# Caddy WAF UI managed - do not edit manually
# domain: example.com | updated: 2026-08-07T12:00:00Z

# Denylist
@ip_deny_example_com {
    remote_ip 198.51.100.44/32 10.0.0.0/8
}
abort @ip_deny_example_com

# Allowlist (if set, all other IPs are denied)
@ip_allow_example_com {
    not remote_ip 203.0.113.5/32
}
abort @ip_allow_example_com
`)

	got, err := parseIPRulesOverlay(content)
	if err != nil {
		t.Fatalf("parse falló: %v", err)
	}
	want := iprules.IPRules{
		Denylist:  []string{"198.51.100.44/32", "10.0.0.0/8"},
		Allowlist: []string{"203.0.113.5/32"},
	}
	if len(got.Denylist) != len(want.Denylist) || len(got.Allowlist) != len(want.Allowlist) {
		t.Fatalf("se esperaba deny=%v allow=%v, se obtuvo deny=%v allow=%v", want.Denylist, want.Allowlist, got.Denylist, got.Allowlist)
	}
	for i := range want.Denylist {
		if got.Denylist[i] != want.Denylist[i] {
			t.Errorf("deny[%d]: se esperaba %q, se obtuvo %q", i, want.Denylist[i], got.Denylist[i])
		}
	}
	for i := range want.Allowlist {
		if got.Allowlist[i] != want.Allowlist[i] {
			t.Errorf("allow[%d]: se esperaba %q, se obtuvo %q", i, want.Allowlist[i], got.Allowlist[i])
		}
	}
}

func TestReadExclusionsMissingFileReturnsNil(t *testing.T) {
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())

	got, err := readExclusions("example.com")
	if err != nil {
		t.Fatalf("overlay inexistente no debe dar error: %v", err)
	}
	if got != nil {
		t.Errorf("sin overlay se esperaba nil, se obtuvo %+v", got)
	}
}

func TestReadIPRulesMissingFileReturnsEmpty(t *testing.T) {
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())

	got, err := readIPRules("example.com")
	if err != nil {
		t.Fatalf("overlay inexistente no debe dar error: %v", err)
	}
	if len(got.Denylist) != 0 || len(got.Allowlist) != 0 {
		t.Errorf("sin overlay se esperaban listas vacías, se obtuvo %+v", got)
	}
}

func TestReadExclusionsRoundTripFromDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CADDY_UI_MANAGED_DIR", dir)

	overlay := []byte("SecRuleRemoveById 942100\n")
	if err := os.WriteFile(filepath.Join(dir, "exclusions-example_com.conf"), overlay, 0640); err != nil {
		t.Fatalf("fallo sembrando overlay: %v", err)
	}

	got, err := readExclusions("example.com")
	if err != nil {
		t.Fatalf("lectura falló: %v", err)
	}
	if len(got) != 1 || got[0].Value != "942100" {
		t.Errorf("se esperaba la exclusión 942100, se obtuvo %+v", got)
	}
}
