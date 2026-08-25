package service

import (
	"errors"
	"fmt"
	"os"

	"github.com/developmi/caddy-waf-ui/internal/caddy"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ErrInvalidMode señala un modo WAF no soportado: los handlers REST lo
// traducen a 400 Bad Request.
var ErrInvalidMode = errors.New("modo WAF inválido: solo se admiten On, Off o DetectionOnly")

// readPreviousState captura los bytes actuales del overlay (si existe) para
// poder restaurarlos si la recarga de Caddy falla (decisión D6).
func readPreviousState(confPath string) ([]byte, bool, error) {
	content, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

// restoreState revierte el overlay a su estado previo (D6): restaura los bytes
// originales si el archivo existía, o lo elimina si no existía. Es el
// equivalente observable de "restaurar el backup del paso 1" sin depender del
// nombre del snapshot (que Fase 4 formaliza con files.RestoreBackup).
func restoreState(confPath string, previous []byte, existed bool) error {
	if !existed {
		if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return files.AtomicWrite(confPath, previous)
}

// chainOpts agrupa las particularidades de cada entrada pública de la cadena
// compartida validate → backup → generate → write → reload → restore → audit
// (hallazgo J5-2): antes vivía copy-pasteada 4 veces (UpdateWAFMode,
// UpdateExclusions, UpdateIPRules, Rollback) y ya había divergido. El flujo de
// error/restore/audit vive una sola vez en runChain; cada entrada aporta sus
// nombres de evento, campos de auditoría y el paso de mutación.
type chainOpts struct {
	// fileType es el tipo de overlay/snapshot: files.FileTypeWAF,
	// files.FileTypeExclusions o files.FileTypeIPRules.
	fileType string
	// confPath es la ruta del overlay gestionado que la cadena escribe.
	confPath string
	// failEvent es el evento de auditoría de los fallos previos a la recarga
	// (p.ej. "waf_mode_failed").
	failEvent string
	// reloadFailEvent es el evento de auditoría del fallo de recarga
	// (p.ej. "waf_mode_changed_but_reload_failed").
	reloadFailEvent string
	// successEvent es el evento de auditoría del éxito (p.ej. "waf_mode_changed").
	successEvent string
	// from es el campo "from" del log de auditoría en TODOS los eventos de la
	// cadena (LogAction normaliza "" → "unknown").
	from string
	// failTo es el campo "to" de los fallos previos a la recarga (suele ser ""
	// salvo UpdateWAFMode, que reporta el modo).
	failTo string
	// to es el campo "to" del fallo de recarga y del éxito (modo, detalle de
	// reglas o tipo de overlay).
	to string
	// mutate produce y escribe los bytes del overlay. Para los cambios
	// (mode/exclusions/ip-rules) es generate + AtomicWrite; para el rollback
	// es files.RestoreBackup. Debe auditar su propio fallo (failEvent) y
	// envolver el error con el mensaje de su etapa.
	mutate func() error
}

// runChain ejecuta la cadena compartida: leer estado previo → backup →
// mutar → recargar Caddy → (si falla) restaurar → auditar (D2/D6). El
// comportamiento de error/restore/audit es idéntico para las cuatro entradas:
// los mensajes de error que los tests asertan ("error leyendo estado previo",
// "error creando backup", "error recargando Caddy", "error restaurando
// overlay") se generan AQUÍ.
func runChain(domainName, remoteIP string, opts chainOpts) error {
	previous, existed, err := readPreviousState(opts.confPath)
	if err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "read error: "+err.Error())
		return fmt.Errorf("error leyendo estado previo: %w", err)
	}

	if err := files.Backup(domainName, opts.fileType); err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "backup error: "+err.Error())
		return fmt.Errorf("error creando backup: %w", err)
	}

	if err := opts.mutate(); err != nil {
		return err
	}

	if err := caddy.Reload(); err != nil {
		restoreErr := restoreState(opts.confPath, previous, existed)
		reloadStatus := fmt.Sprintf("failed: %v", err)
		if restoreErr != nil {
			reloadStatus = fmt.Sprintf("failed: %v (restore error: %v)", err, restoreErr)
		}
		logs.LogAction(opts.reloadFailEvent, domainName, opts.from, opts.to, remoteIP, reloadStatus)
		if restoreErr != nil {
			return fmt.Errorf("error recargando Caddy: %v; error restaurando overlay: %w", err, restoreErr)
		}
		return fmt.Errorf("error recargando Caddy: %w", err)
	}

	logs.LogAction(opts.successEvent, domainName, opts.from, opts.to, remoteIP, "success")
	return nil
}

// UpdateWAFMode ejecuta la cadena compartida validate → backup → generate →
// write → reload → audit para el modo del motor WAF (D2/D6).
func UpdateWAFMode(domainName string, mode domain.WAFMode, remoteIP string) error {
	// Validación estricta del dominio ANTES de cualquier uso en rutas,
	// plantillas o backups (hallazgo J2): bloquea la inyección de directivas
	// Caddyfile vía la cabecera "# domain:" y el path traversal de backups.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}

	if mode != domain.ModeOn && mode != domain.ModeOff && mode != domain.ModeDetectionOnly {
		return ErrInvalidMode
	}

	site := &domain.Site{Domain: domainName, Mode: mode}
	opts := chainOpts{
		fileType:        files.FileTypeWAF,
		confPath:        files.WAFConfigPath(config.ManagedDir(), domainName),
		failEvent:       "waf_mode_failed",
		reloadFailEvent: "waf_mode_changed_but_reload_failed",
		successEvent:    "waf_mode_changed",
		from:            "unknown",
		failTo:          string(mode),
		to:              string(mode),
	}
	opts.mutate = func() error {
		snippet, err := waf.GenerateSnippet(site, config.AuditLogPath(), config.IncludeDir())
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "generate error: "+err.Error())
			return fmt.Errorf("error generando configuración: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error escribiendo configuración: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// UpdateExclusions ejecuta la cadena compartida para las exclusiones CRS del
// dominio, incluyendo las targeteadas por parámetro ARGS:<param> (D5).
func UpdateExclusions(domainName string, exclusions []waf.Exclusion, remoteIP string) error {
	// Validación estricta del dominio ANTES de cualquier uso en rutas,
	// plantillas o backups (hallazgo J2): bloquea la inyección de directivas
	// Caddyfile vía la cabecera "# domain:" y el path traversal de backups.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}

	if err := waf.ValidateExclusions(exclusions); err != nil {
		return err
	}

	site := &domain.Site{Domain: domainName}
	opts := chainOpts{
		fileType:        files.FileTypeExclusions,
		confPath:        files.ExclusionsConfigPath(config.ManagedDir(), domainName),
		failEvent:       "exclusions_failed",
		reloadFailEvent: "exclusions_changed_but_reload_failed",
		successEvent:    "exclusions_updated",
		to:              fmt.Sprintf("%d rules", len(exclusions)),
	}
	opts.mutate = func() error {
		snippet, err := waf.GenerateExclusions(site, exclusions)
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "generate error: "+err.Error())
			return fmt.Errorf("error generando configuración: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error escribiendo configuración: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// UpdateIPRules ejecuta la cadena compartida para las listas allow/deny del
// dominio. Las entradas IP se validan y normalizan ANTES del backup.
func UpdateIPRules(domainName string, rules iprules.IPRules, remoteIP string) error {
	// Validación estricta del dominio ANTES de cualquier uso en rutas,
	// plantillas o backups (hallazgo J2): bloquea la inyección de directivas
	// Caddyfile vía la cabecera "# domain:" y el path traversal de backups.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}

	if err := iprules.ValidateIPRules(rules); err != nil {
		return err
	}

	site := &domain.Site{Domain: domainName}
	opts := chainOpts{
		fileType:        files.FileTypeIPRules,
		confPath:        files.IPRulesConfigPath(config.ManagedDir(), domainName),
		failEvent:       "iprules_failed",
		reloadFailEvent: "iprules_changed_but_reload_failed",
		successEvent:    "iprules_updated",
		to:              fmt.Sprintf("allow:%d deny:%d", len(rules.Allowlist), len(rules.Denylist)),
	}
	opts.mutate = func() error {
		snippet, err := iprules.GenerateSnippet(site, rules)
		if err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "generate error: "+err.Error())
			return fmt.Errorf("error generando configuración: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error escribiendo configuración: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// Rollback restaura un snapshot de configuración (nombre completo
// {ISO8601}.{tipo}.conf) sobre el overlay de su tipo a través de la cadena
// compartida: validar → respaldar estado actual → restaurar bytes → recargar
// → auditar. Si la recarga falla, el overlay vuelve al estado previo (D6).
func Rollback(domainName, backupID, remoteIP string) error {
	// Validación estricta del dominio ANTES de cualquier uso en rutas,
	// plantillas o backups (hallazgo J2): bloquea la inyección de directivas
	// Caddyfile vía la cabecera "# domain:" y el path traversal de backups.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}

	// 0. Validar el nombre del snapshot y derivar tipo + ruta conf ANTES de
	//    mutar estado (fail-fast; el patrón estricto bloquea path traversal).
	fileType, err := files.BackupType(backupID)
	if err != nil {
		logs.LogAction("rollback_failed", domainName, backupID, "", remoteIP, err.Error())
		return err
	}
	confPath, err := files.OverlayPath(config.ManagedDir(), fileType, domainName)
	if err != nil {
		logs.LogAction("rollback_failed", domainName, backupID, "", remoteIP, err.Error())
		return err
	}

	opts := chainOpts{
		fileType:        fileType,
		confPath:        confPath,
		failEvent:       "rollback_failed",
		reloadFailEvent: "rollback_changed_but_reload_failed",
		successEvent:    "rollback_restored",
		from:            backupID,
		to:              fileType,
	}
	opts.mutate = func() error {
		// Restaurar los bytes del snapshot elegido sobre el overlay (bytes → conf).
		if err := files.RestoreBackup(domainName, backupID); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "restore error: "+err.Error())
			return fmt.Errorf("error restaurando snapshot: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}
