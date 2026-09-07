package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// The parsers read EXCLUSIVELY the format that this project generates
// (waf/exclusions.go and iprules/rules.go): the round-trip must be exact.

func TestParseExclusionsOverlayURLLevelAndTargeted(t *testing.T) {
	content := []byte(`# Caddy WAF UI managed - do not edit manually
# domain: example.com | updated: 2026-08-07T12:00:00Z

SecRuleRemoveById 942100
SecRule ARGS:q "@unconditionalMatch" "id:9000001,phase:2,pass,nolog,ctl:ruleRemoveById=942100"
SecRuleRemoveByTag "php-code-injection"
SecRule ARGS:cmd "@unconditionalMatch" "id:9000002,phase:2,pass,nolog,ctl:ruleRemoveByTag=rce"
# stray comment that must be ignored
`)

	got, err := parseExclusionsOverlay(content)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	want := []waf.Exclusion{
		{Type: waf.ExcludeByID, Value: "942100"},
		{Type: waf.ExcludeByID, Value: "942100", Param: "q"},
		{Type: waf.ExcludeByTag, Value: "php-code-injection"},
		{Type: waf.ExcludeByTag, Value: "rce", Param: "cmd"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d exclusions, got %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}

func TestParseExclusionsOverlayEmpty(t *testing.T) {
	got, err := parseExclusionsOverlay([]byte("# No exclusions configured for this domain.\n"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("without rules the parse must return an empty list, got %+v", got)
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
		t.Fatalf("parse failed: %v", err)
	}
	want := iprules.IPRules{
		Denylist:  []string{"198.51.100.44/32", "10.0.0.0/8"},
		Allowlist: []string{"203.0.113.5/32"},
	}
	if len(got.Denylist) != len(want.Denylist) || len(got.Allowlist) != len(want.Allowlist) {
		t.Fatalf("expected deny=%v allow=%v, got deny=%v allow=%v", want.Denylist, want.Allowlist, got.Denylist, got.Allowlist)
	}
	for i := range want.Denylist {
		if got.Denylist[i] != want.Denylist[i] {
			t.Errorf("deny[%d]: expected %q, got %q", i, want.Denylist[i], got.Denylist[i])
		}
	}
	for i := range want.Allowlist {
		if got.Allowlist[i] != want.Allowlist[i] {
			t.Errorf("allow[%d]: expected %q, got %q", i, want.Allowlist[i], got.Allowlist[i])
		}
	}
}

func TestReadExclusionsMissingFileReturnsNil(t *testing.T) {
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())

	got, err := readExclusions("example.com")
	if err != nil {
		t.Fatalf("a nonexistent overlay must not return an error: %v", err)
	}
	if got != nil {
		t.Errorf("without an overlay nil was expected, got %+v", got)
	}
}

func TestReadIPRulesMissingFileReturnsEmpty(t *testing.T) {
	t.Setenv("CADDY_UI_MANAGED_DIR", t.TempDir())

	got, err := readIPRules("example.com")
	if err != nil {
		t.Fatalf("a nonexistent overlay must not return an error: %v", err)
	}
	if len(got.Denylist) != 0 || len(got.Allowlist) != 0 {
		t.Errorf("without an overlay empty lists were expected, got %+v", got)
	}
}

func TestReadExclusionsRoundTripFromDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CADDY_UI_MANAGED_DIR", dir)

	overlay := []byte("SecRuleRemoveById 942100\n")
	if err := os.WriteFile(filepath.Join(dir, "exclusions-example_com.conf"), overlay, 0640); err != nil {
		t.Fatalf("failed seeding overlay: %v", err)
	}

	got, err := readExclusions("example.com")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(got) != 1 || got[0].Value != "942100" {
		t.Errorf("expected the exclusion 942100, got %+v", got)
	}
}
