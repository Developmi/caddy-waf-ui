package waf_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

func TestGenerateExclusions(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	testCases := []struct {
		name       string
		exclusions []waf.Exclusion
		wantErr    bool
		fragments  []string
		notIn      []string
	}{
		{
			name: "valid id",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100"},
			},
			wantErr: false,
			fragments: []string{
				"SecRuleRemoveById 941100",
			},
		},
		{
			name: "URI-level exclusion without parameter",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: ""},
			},
			wantErr: false,
			fragments: []string{
				"SecRuleRemoveById 941100",
			},
			notIn: []string{"ARGS:"},
		},
		{
			name: "exclusion with parameter q generates id 9000001 and target ARGS:q",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				`SecRule ARGS:q "@unconditionalMatch" "id:9000001,phase:2,pass,nolog,ctl:ruleRemoveById=941100"`,
			},
			notIn: []string{"SecRuleRemoveById 941100\n"},
		},
		{
			name: "two parameterized exclusions get consecutive ids 9000001 and 9000002",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q"},
				{Type: waf.ExcludeByID, Value: "942100", Param: "id"},
			},
			wantErr: false,
			fragments: []string{
				"id:9000001", "ARGS:q",
				"id:9000002", "ARGS:id",
			},
		},
		{
			name: "duplicates deduplicated: same type+value+param does not consume a new id",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q"},
				{Type: waf.ExcludeByID, Value: "941100", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				"id:9000001", "ARGS:q", "ctl:ruleRemoveById=941100",
			},
			notIn: []string{"9000002"},
		},
		{
			name: "tag with parameter generates targeted ruleRemoveByTag",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				`ctl:ruleRemoveByTag=attack-xss`, "ARGS:q",
			},
		},
		{
			name: "parameter with only spaces rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: " "},
			},
			wantErr: true,
		},
		{
			name: "parameter with newline rejected",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "valid tag",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss"},
			},
			wantErr: false,
			fragments: []string{
				`SecRuleRemoveByTag "attack-xss"`,
			},
		},
		{
			name: "id with newline",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "tag with quotes",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: `attack-xss" }`},
			},
			wantErr: true,
		},
		{
			name: "unknown type",
			exclusions: []waf.Exclusion{
				{Type: waf.ExclusionType("uri"), Value: "/api/v1"},
			},
			wantErr: true,
		},
		{
			name: "value with hash",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100#comment"},
			},
			wantErr: true,
		},
		{
			name: "id with space",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100 942100"},
			},
			wantErr: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resultBytes, err := waf.GenerateExclusions(site, tt.exclusions)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GenerateExclusions should fail with %+v, but it returned no error", tt.exclusions)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateExclusions failed unexpectedly: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("the generated block does not contain the expected fragment: %q\nBlock:\n%s", fragment, result)
				}
			}

			for _, fragment := range tt.notIn {
				if strings.Contains(result, fragment) {
					t.Errorf("the generated block must NOT contain the fragment: %q\nBlock:\n%s", fragment, result)
				}
			}
		})
	}
}
