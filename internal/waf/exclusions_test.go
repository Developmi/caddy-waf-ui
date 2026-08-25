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
			name: "id válido",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100"},
			},
			wantErr: false,
			fragments: []string{
				"SecRuleRemoveById 941100",
			},
		},
		{
			name: "exclusión de nivel URI sin parámetro",
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
			name: "exclusión con parámetro q genera id 9000001 y target ARGS:q",
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
			name: "dos exclusions con parámetro reciben ids consecutivos 9000001 y 9000002",
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
			name: "duplicados deduplicados: misma type+value+param no consume id nuevo",
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
			name: "tag con parámetro genera ruleRemoveByTag targeteado",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss", Param: "q"},
			},
			wantErr: false,
			fragments: []string{
				`ctl:ruleRemoveByTag=attack-xss`, "ARGS:q",
			},
		},
		{
			name: "parámetro solo con espacios rechazado",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: " "},
			},
			wantErr: true,
		},
		{
			name: "parámetro con salto de línea rechazado",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100", Param: "q\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "tag válido",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: "attack-xss"},
			},
			wantErr: false,
			fragments: []string{
				`SecRuleRemoveByTag "attack-xss"`,
			},
		},
		{
			name: "id con salto de línea",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100\nSecRuleEngine Off"},
			},
			wantErr: true,
		},
		{
			name: "tag con comillas",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByTag, Value: `attack-xss" }`},
			},
			wantErr: true,
		},
		{
			name: "tipo desconocido",
			exclusions: []waf.Exclusion{
				{Type: waf.ExclusionType("uri"), Value: "/api/v1"},
			},
			wantErr: true,
		},
		{
			name: "valor con numeral",
			exclusions: []waf.Exclusion{
				{Type: waf.ExcludeByID, Value: "941100#comment"},
			},
			wantErr: true,
		},
		{
			name: "id con espacio",
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
					t.Fatalf("GenerateExclusions debería fallar con %+v, pero no devolvió error", tt.exclusions)
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateExclusions falló inesperadamente: %v", err)
			}

			result := string(resultBytes)

			for _, fragment := range tt.fragments {
				if !strings.Contains(result, fragment) {
					t.Errorf("El bloque generado no contiene el fragmento esperado: %q\nBloque:\n%s", fragment, result)
				}
			}

			for _, fragment := range tt.notIn {
				if strings.Contains(result, fragment) {
					t.Errorf("El bloque generado NO debería contener el fragmento: %q\nBloque:\n%s", fragment, result)
				}
			}
		})
	}
}
