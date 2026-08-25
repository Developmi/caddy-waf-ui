package logs

// AuditEntry es una entrada del log de auditoría de Coraza (decisión D7).
// El lector de la Fase 3 (internal/logs/reader.go) la poblará parseando el
// JSONL de CADDY_UI_AUDIT_LOG; la UI SSR ya consume este shape para renderizar
// el explorador de logs y la vista previa del overview.
type AuditEntry struct {
	Timestamp string
	RuleID    string
	Client    string
	URI       string
	Action    string
	Message   string
}
