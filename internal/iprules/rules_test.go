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
			name: "cidr válido",
			rules: iprules.IPRules{
				Denylist: []string{"10.0.0.0/8"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip 10.0.0.0/8",
			},
		},
		{
			name: "ip suelta se normaliza a /32",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip 1.2.3.4/32",
			},
		},
		{
			name: "ipv6 válido",
			rules: iprules.IPRules{
				Denylist: []string{"::1/128"},
			},
			wantErr: false,
			fragments: []string{
				"remote_ip ::1/128",
			},
		},
		{
			name: "string con salto de línea",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}\nabort @foo"},
			},
			wantErr: true,
		},
		{
			name: "string con llave de cierre",
			rules: iprules.IPRules{
				Denylist: []string{"1.2.3.4}"},
			},
			wantErr: true,
		},
		{
			name: "basura",
			rules: iprules.IPRules{
				Denylist: []string{"not-an-ip"},
			},
			wantErr: true,
		},
		{
			name: "allowlist también se normaliza",
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
					t.Fatalf("GenerateSnippet debería fallar con %+v, pero no devolvió error", tt.rules)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateSnippet falló inesperadamente: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("El bloque generado no contiene el fragmento esperado: %q\nBloque:\n%s", fragment, result)
				}
			}
		})
	}
}
