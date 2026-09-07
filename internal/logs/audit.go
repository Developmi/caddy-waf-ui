package logs

// AuditEntry is an entry of the Coraza audit log (decision D7).
// The Phase 3 reader (internal/logs/reader.go) will populate it by parsing
// the JSONL of CADDY_UI_AUDIT_LOG; the SSR UI already consumes this shape to
// render the log explorer and the overview preview.
type AuditEntry struct {
	Timestamp string
	RuleID    string
	Client    string
	URI       string
	Action    string
	Message   string
}
