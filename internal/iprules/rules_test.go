package iprules_test

import (
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
)

func TestGenerateSnippet(t *testing.T) {
	site := &domain.Site{
		Domain: "api.developmi.com",
		Mode:   domain.ModeDetectionOnly,
	}

	testCases := []struct {
		name      string
		rules     iprules.IPRules
		wantErr   bool
		fragments []string
	}{
		{
			name: "valid CIDR",
			rules: iprules.IPRules{
				Denylist: []string{"10.0.0.0/8"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip 10.0.0.0/8",
			},
		},
		{
			name: "bare IP is normalized to /32",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip 1.2.3.4/32",
			},
		},
		{
			name: "valid IPv6",
			rules: iprules.IPRules{
				Denylist: []string{"::1/128"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip ::1/128",
			},
		},
		{
			name: "string with newline",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}\nabort @foo"},
			},
			wantErr: true,
		},
		{
			name: "string with closing brace",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}"},
			},
			wantErr: true,
		},
		{
			name: "garbage",
			rules: iprules.IPRules{
				Denylist: []string{"not-an-ip"},
			},
			wantErr: true,
		},
		{
			name: "allowlist is normalized too",
			rules: iprules.IPRules{
				Allowlist: []string{"203.0.113.5"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip 203.0.113.5/32",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			resultBytes, err := iprules.GenerateSnippet(site, tt.rules)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("GenerateSnippet should fail with %+v, but returned no error", tt.rules)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateSnippet failed unexpectedly: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("the generated block does not contain the expected fragment: %q\nBlock:\n%s", fragment, result)
				}
			}
		})
	}
}
