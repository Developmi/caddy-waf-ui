package ui

import (
	"os"
	"regexp"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// The overlay parsers read EXCLUSIVELY the format that this project
// generates (waf/exclusions.go and iprules/rules.go), guaranteeing an exact
// round-trip. Their purpose is twofold:
//  1. Render the active exclusions/IP rules lists in the SSR views (task 2.5)
//     without inventing third-party readers.
//  2. Allow the "add" forms (task 2.6) to merge the new rule with the current
//     state BEFORE calling the shared chain (which replaces the complete
//     list): without this, adding a rule would silently delete the existing
//     ones.
var (
	exclusionURLLine   = regexp.MustCompile(`^SecRuleRemoveById\s+(\d+)$`)
	exclusionTagLine   = regexp.MustCompile(`^SecRuleRemoveByTag\s+"([A-Za-z0-9_-]+)"$`)
	exclusionTargetID  = regexp.MustCompile(`^SecRule ARGS:([A-Za-z0-9_-]+)\s+"@unconditionalMatch"\s+"id:\d+,phase:2,pass,nolog,ctl:ruleRemoveById=(\d+)"$`)
	exclusionTargetTag = regexp.MustCompile(`^SecRule ARGS:([A-Za-z0-9_-]+)\s+"@unconditionalMatch"\s+"id:\d+,phase:2,pass,nolog,ctl:ruleRemoveByTag=([A-Za-z0-9_-]+)"$`)
	ipRulesDenyLine    = regexp.MustCompile(`^\s*remote_ip\s+(.+)$`)
	ipRulesAllowLine   = regexp.MustCompile(`^\s*not remote_ip\s+(.+)$`)
)

// parseExclusionsOverlay extracts the exclusions of the generated overlay.
// Unknown lines (comments, headers) are ignored: the parser only recognizes
// directives that the generator itself writes.
func parseExclusionsOverlay(content []byte) ([]waf.Exclusion, error) {
	var exclusions []waf.Exclusion
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case exclusionURLLine.MatchString(trimmed):
			m := exclusionURLLine.FindStringSubmatch(trimmed)
			exclusions = append(exclusions, waf.Exclusion{Type: waf.ExcludeByID, Value: m[1]})
		case exclusionTagLine.MatchString(trimmed):
			m := exclusionTagLine.FindStringSubmatch(trimmed)
			exclusions = append(exclusions, waf.Exclusion{Type: waf.ExcludeByTag, Value: m[1]})
		case exclusionTargetID.MatchString(trimmed):
			m := exclusionTargetID.FindStringSubmatch(trimmed)
			exclusions = append(exclusions, waf.Exclusion{Type: waf.ExcludeByID, Value: m[2], Param: m[1]})
		case exclusionTargetTag.MatchString(trimmed):
			m := exclusionTargetTag.FindStringSubmatch(trimmed)
			exclusions = append(exclusions, waf.Exclusion{Type: waf.ExcludeByTag, Value: m[2], Param: m[1]})
		}
	}
	return exclusions, nil
}

// parseIPRulesOverlay extracts the allow/deny lists of the generated
// overlay. "not remote_ip ..." (allowlist) does not collide with "remote_ip
// ..." (denylist) because the "not " prefix prevents the match of the first
// pattern.
func parseIPRulesOverlay(content []byte) (iprules.IPRules, error) {
	var rules iprules.IPRules
	for _, line := range strings.Split(string(content), "\n") {
		if m := ipRulesDenyLine.FindStringSubmatch(line); m != nil {
			rules.Denylist = append(rules.Denylist, strings.Fields(m[1])...)
		}
		if m := ipRulesAllowLine.FindStringSubmatch(line); m != nil {
			rules.Allowlist = append(rules.Allowlist, strings.Fields(m[1])...)
		}
	}
	return rules, nil
}

// readExclusions returns the active exclusions of the domain, or nil if the
// overlay does not exist yet (first configuration).
func readExclusions(domainName string) ([]waf.Exclusion, error) {
	return readExclusionsFile(files.ExclusionsConfigPath(managedDir(), domainName))
}

// readExclusionsFile reads and parses an exclusions overlay by path.
func readExclusionsFile(path string) ([]waf.Exclusion, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseExclusionsOverlay(content)
}

// readIPRules returns the active IP rules of the domain, or empty lists if
// the overlay does not exist yet.
func readIPRules(domainName string) (iprules.IPRules, error) {
	return readIPRulesFile(files.IPRulesConfigPath(managedDir(), domainName))
}

// readIPRulesFile reads and parses an IP rules overlay by path.
func readIPRulesFile(path string) (iprules.IPRules, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return iprules.IPRules{}, nil
	}
	if err != nil {
		return iprules.IPRules{}, err
	}
	return parseIPRulesOverlay(content)
}
