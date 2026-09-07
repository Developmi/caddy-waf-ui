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

// ErrInvalidMode signals an unsupported WAF mode: REST handlers translate it
// to 400 Bad Request.
var ErrInvalidMode = errors.New("invalid WAF mode: only On, Off or DetectionOnly are supported")

// readPreviousState captures the current bytes of the overlay (if it exists)
// so they can be restored if the Caddy reload fails (decision D6).
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

// restoreState reverts the overlay to its previous state (D6): it restores
// the original bytes if the file existed, or removes it if it did not. It is
// the observable equivalent of "restoring the backup of step 1" without
// depending on the snapshot name (which Phase 4 formalizes with
// files.RestoreBackup).
func restoreState(confPath string, previous []byte, existed bool) error {
	if !existed {
		if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return files.AtomicWrite(confPath, previous)
}

// chainOpts groups the particularities of each public entry of the shared
// chain validate → backup → generate → write → reload → restore → audit
// (finding J5-2): it used to be copy-pasted 4 times (UpdateWAFMode,
// UpdateExclusions, UpdateIPRules, Rollback) and had already diverged. The
// error/restore/audit flow lives once in runChain; each entry contributes its
// event names, audit fields and the mutation step.
type chainOpts struct {
	// fileType is the overlay/snapshot type: files.FileTypeWAF,
	// files.FileTypeExclusions or files.FileTypeIPRules.
	fileType string
	// confPath is the path of the managed overlay that the chain writes.
	confPath string
	// failEvent is the audit event of the failures prior to the reload
	// (e.g. "waf_mode_failed").
	failEvent string
	// reloadFailEvent is the audit event of the reload failure
	// (e.g. "waf_mode_changed_but_reload_failed").
	reloadFailEvent string
	// successEvent is the audit event of the success (e.g. "waf_mode_changed").
	successEvent string
	// from is the "from" field of the audit log in ALL the events of the
	// chain (LogAction normalizes "" → "unknown").
	from string
	// failTo is the "to" field of the failures prior to the reload (usually
	// "" except UpdateWAFMode, which reports the mode).
	failTo string
	// to is the "to" field of the reload failure and of the success (mode,
	// rules detail or overlay type).
	to string
	// mutate produces and writes the overlay bytes. For the changes
	// (mode/exclusions/ip-rules) it is generate + AtomicWrite; for the
	// rollback it is files.RestoreBackup. It must audit its own failure
	// (failEvent) and wrap the error with the message of its stage.
	mutate func() error
}

// runChain runs the shared chain: read previous state → backup → mutate →
// reload Caddy → (on failure) restore → audit (D2/D6). The
// error/restore/audit behavior is identical for the four entries: the error
// messages that the tests assert ("error reading previous state", "error
// creating backup", "error reloading Caddy", "error restoring overlay") are
// generated HERE.
func runChain(domainName, remoteIP string, opts chainOpts) error {
	previous, existed, err := readPreviousState(opts.confPath)
	if err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "read error: "+err.Error())
		return fmt.Errorf("error reading previous state: %w", err)
	}

	if err := files.Backup(domainName, opts.fileType); err != nil {
		logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "backup error: "+err.Error())
		return fmt.Errorf("error creating backup: %w", err)
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
			return fmt.Errorf("error reloading Caddy: %v; error restoring overlay: %w", err, restoreErr)
		}
		return fmt.Errorf("error reloading Caddy: %w", err)
	}

	logs.LogAction(opts.successEvent, domainName, opts.from, opts.to, remoteIP, "success")
	return nil
}

// UpdateWAFMode runs the shared chain validate → backup → generate →
// write → reload → audit for the WAF engine mode (D2/D6).
func UpdateWAFMode(domainName string, mode domain.WAFMode, remoteIP string) error {
	// Strict domain validation BEFORE any use in paths, templates or backups
	// (finding J2): it blocks Caddyfile directive injection via the
	// "# domain:" header and backup path traversal.
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
			return fmt.Errorf("error generating configuration: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error writing configuration: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// UpdateExclusions runs the shared chain for the CRS exclusions of the
// domain, including the ones targeted by the ARGS:<param> parameter (D5).
func UpdateExclusions(domainName string, exclusions []waf.Exclusion, remoteIP string) error {
	// Strict domain validation BEFORE any use in paths, templates or backups
	// (finding J2): it blocks Caddyfile directive injection via the
	// "# domain:" header and backup path traversal.
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
			return fmt.Errorf("error generating configuration: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error writing configuration: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// UpdateIPRules runs the shared chain for the allow/deny lists of the
// domain. The IP entries are validated and normalized BEFORE the backup.
func UpdateIPRules(domainName string, rules iprules.IPRules, remoteIP string) error {
	// Strict domain validation BEFORE any use in paths, templates or backups
	// (finding J2): it blocks Caddyfile directive injection via the
	// "# domain:" header and backup path traversal.
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
			return fmt.Errorf("error generating configuration: %w", err)
		}
		if err := files.AtomicWrite(opts.confPath, snippet); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "write error: "+err.Error())
			return fmt.Errorf("error writing configuration: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}

// Rollback restores a configuration snapshot (full name {ISO8601}.{type}.conf)
// over the overlay of its type through the shared chain: validate → back up
// the current state → restore bytes → reload → audit. If the reload fails,
// the overlay returns to the previous state (D6).
func Rollback(domainName, backupID, remoteIP string) error {
	// Strict domain validation BEFORE any use in paths, templates or backups
	// (finding J2): it blocks Caddyfile directive injection via the
	// "# domain:" header and backup path traversal.
	if err := ValidateDomain(domainName); err != nil {
		return err
	}

	// 0. Validate the snapshot name and derive type + conf path BEFORE
	//    mutating any state (fail-fast; the strict pattern blocks path
	//    traversal).
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
		// Restore the bytes of the chosen snapshot over the overlay (bytes → conf).
		if err := files.RestoreBackup(domainName, backupID); err != nil {
			logs.LogAction(opts.failEvent, domainName, opts.from, opts.failTo, remoteIP, "restore error: "+err.Error())
			return fmt.Errorf("error restoring snapshot: %w", err)
		}
		return nil
	}
	return runChain(domainName, remoteIP, opts)
}
