package ui

import (
	"os"
	"regexp"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// Los parsers de overlay leen EXCLUSIVAMENTE el formato que genera este
// proyecto (waf/exclusions.go e iprules/rules.go), garantizando un
// round-trip exacto. Su propósito es doble:
//  1. Renderizar las listas activas de exclusiones/reglas IP en las vistas
//     SSR (task 2.5) sin inventar lectores de terceros.
//  2. Permitir que los formularios "add" (task 2.6) fusionen la regla nueva
//     con el estado actual ANTES de llamar a la cadena compartida (que
//     reemplaza la lista completa): sin esto, agregar una regla borraría
//     silenciosamente las existentes.
var (
	exclusionURLLine   = regexp.MustCompile(`^SecRuleRemoveById\s+(\d+)$`)
	exclusionTagLine   = regexp.MustCompile(`^SecRuleRemoveByTag\s+"([A-Za-z0-9_-]+)"$`)
	exclusionTargetID  = regexp.MustCompile(`^SecRule ARGS:([A-Za-z0-9_-]+)\s+"@unconditionalMatch"\s+"id:\d+,phase:2,pass,nolog,ctl:ruleRemoveById=(\d+)"$`)
	exclusionTargetTag = regexp.MustCompile(`^SecRule ARGS:([A-Za-z0-9_-]+)\s+"@unconditionalMatch"\s+"id:\d+,phase:2,pass,nolog,ctl:ruleRemoveByTag=([A-Za-z0-9_-]+)"$`)
	ipRulesDenyLine    = regexp.MustCompile(`^\s*remote_ip\s+(.+)$`)
	ipRulesAllowLine   = regexp.MustCompile(`^\s*not remote_ip\s+(.+)$`)
)

// parseExclusionsOverlay extrae las exclusiones del overlay generado.
// Las líneas desconocidas (comentarios, cabeceras) se ignoran: el parser
// solo reconoce directivas que el propio generador escribe.
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

// parseIPRulesOverlay extrae las listas allow/deny del overlay generado.
// "not remote_ip ..." (allowlist) no colisiona con "remote_ip ..."
// (denylist) porque el prefijo "not " impide el match del primer patrón.
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

// readExclusions devuelve las exclusiones activas del dominio, o nil si el
// overlay aún no existe (primera configuración).
func readExclusions(domainName string) ([]waf.Exclusion, error) {
	return readExclusionsFile(files.ExclusionsConfigPath(managedDir(), domainName))
}

// readExclusionsFile lee y parsea un overlay de exclusiones por ruta.
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

// readIPRules devuelve las reglas IP activas del dominio, o listas vacías si
// el overlay aún no existe.
func readIPRules(domainName string) (iprules.IPRules, error) {
	return readIPRulesFile(files.IPRulesConfigPath(managedDir(), domainName))
}

// readIPRulesFile lee y parsea un overlay de reglas IP por ruta.
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
