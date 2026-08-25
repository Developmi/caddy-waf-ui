package logs

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Fixtures del formato JSON de Coraza v3 (SecAuditLogFormat JSON, coraza
// internal/auditlog: transaction.{timestamp,id,client_ip,is_interrupted,
// request.uri} + messages[].{message,actionset,data.id}).
var (
	fixtureValid     = filepath.Join("testdata", "audit-valid.jsonl")
	fixtureMalformed = filepath.Join("testdata", "audit-malformed.jsonl")
)

// captureLogs redirige slog a un buffer y lo restaura al terminar el test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestReadParsesCorazaJSONLNewestFirst(t *testing.T) {
	got, err := Read(fixtureValid, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("se esperaban 3 entradas, se obtuvieron %d", len(got.Entries))
	}
	// El log crece hacia el final: la lectura devuelve lo más reciente primero.
	if got.Entries[0].RuleID != "910000" || got.Entries[2].RuleID != "942100" {
		t.Errorf("el orden debe ser newest-first (910000, 920420, 942100), se obtuvo %+v", got.Entries)
	}

	blocked := got.Entries[2] // tx-0001: deny
	if blocked.Timestamp != "2026-08-06T14:23:11Z" {
		t.Errorf("timestamp debe normalizarse a RFC3339, se obtuvo %q", blocked.Timestamp)
	}
	if blocked.Client != "1.2.3.4" {
		t.Errorf("client debe ser 1.2.3.4, se obtuvo %q", blocked.Client)
	}
	if blocked.URI != "/wp-admin/login.php" {
		t.Errorf("uri debe ser /wp-admin/login.php, se obtuvo %q", blocked.URI)
	}
	if blocked.Action != "BLOCKED" {
		t.Errorf("deny debe mapear a BLOCKED, se obtuvo %q", blocked.Action)
	}
	if blocked.Message != "Inbound XSS Attack Detected" {
		t.Errorf("message debe ser el mensaje de la primera regla, se obtuvo %q", blocked.Message)
	}

	detected := got.Entries[1] // tx-0002: pass
	if detected.Action != "DETECTED" {
		t.Errorf("pass debe mapear a DETECTED, se obtuvo %q", detected.Action)
	}
	allowed := got.Entries[0] // tx-0003: allow
	if allowed.Action != "DETECTED" {
		t.Errorf("allow debe mapear a DETECTED, se obtuvo %q", allowed.Action)
	}
	if allowed.Timestamp != "2026-08-06T14:26:07Z" {
		t.Errorf("timestamp tx-0003 debe ser RFC3339, se obtuvo %q", allowed.Timestamp)
	}
}

func TestReadFiltersByAction(t *testing.T) {
	got, err := Read(fixtureValid, Options{Action: "BLOCKED"})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].RuleID != "942100" {
		t.Fatalf("actionFilter=BLOCKED debe dejar solo la entrada deny, se obtuvo %+v", got.Entries)
	}
	if got.Total != 1 {
		t.Errorf("Total debe reflejar la lista filtrada, se obtuvo %d", got.Total)
	}
}

func TestReadFiltersBySearchCaseInsensitive(t *testing.T) {
	cases := []struct {
		search string
		wantID string
	}{
		{"1.2.3.4", "942100"},  // client_ip
		{"WP-ADMIN", "942100"}, // uri, case-insensitive
		{"942100", "942100"},   // rule id
		{"xss attack", "942100"},
		{"203.0.113.9", "920420"},
		{"no-existe", ""},
	}
	for _, tc := range cases {
		got, err := Read(fixtureValid, Options{Search: tc.search})
		if err != nil {
			t.Fatalf("Read(search=%q) falló: %v", tc.search, err)
		}
		if tc.wantID == "" {
			if len(got.Entries) != 0 {
				t.Errorf("search=%q no debe matchear nada, se obtuvieron %d", tc.search, len(got.Entries))
			}
			continue
		}
		if len(got.Entries) != 1 || got.Entries[0].RuleID != tc.wantID {
			t.Errorf("search=%q debe devolver %s, se obtuvo %+v", tc.search, tc.wantID, got.Entries)
		}
	}
}

func TestReadPaginates(t *testing.T) {
	page1, err := Read(fixtureValid, Options{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(page1.Entries) != 2 || page1.Entries[0].RuleID != "910000" || page1.Entries[1].RuleID != "920420" {
		t.Fatalf("página 1 debe traer 910000 y 920420, se obtuvo %+v", page1.Entries)
	}
	if page1.Total != 3 || page1.Pages != 2 {
		t.Errorf("Total=3, Pages=2 esperados, se obtuvo Total=%d Pages=%d", page1.Total, page1.Pages)
	}

	page2, err := Read(fixtureValid, Options{Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(page2.Entries) != 1 || page2.Entries[0].RuleID != "942100" {
		t.Fatalf("página 2 debe traer 942100, se obtuvo %+v", page2.Entries)
	}

	// Página fuera de rango: se recorta a la última.
	out, err := Read(fixtureValid, Options{Page: 9, PageSize: 2})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if out.Page != 2 || len(out.Entries) != 1 {
		t.Errorf("page=9 debe recortarse a la última página (2), se obtuvo page=%d len=%d", out.Page, len(out.Entries))
	}

	// Valores por defecto: pageSize 50, page 1.
	def, err := Read(fixtureValid, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if def.Page != 1 || def.PageSize != 50 || def.Pages != 1 {
		t.Errorf("defaults esperados page=1 pageSize=50 pages=1, se obtuvo page=%d pageSize=%d pages=%d", def.Page, def.PageSize, def.Pages)
	}
}

func TestReadMalformedLinesLoggedWithLineNumber(t *testing.T) {
	logs := captureLogs(t)

	got, err := Read(fixtureMalformed, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	// Las líneas válidas (1 y 4) sobreviven; las inválidas (2, 3 y 5) se loguean.
	if len(got.Entries) != 2 {
		t.Fatalf("se esperaban 2 entradas válidas, se obtuvieron %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].RuleID != "920420" || got.Entries[1].RuleID != "932100" {
		t.Errorf("orden newest-first esperado (920420, 932100), se obtuvo %+v", got.Entries)
	}
	// Spec audit-logs: una línea no parseable nunca se descarta en silencio.
	out := logs.String()
	if !strings.Contains(out, "no parseable") {
		t.Errorf("el error debe loguearse con slog.Error, salida: %s", out)
	}
	for _, line := range []string{"line=2", "line=3", "line=5"} {
		if !strings.Contains(out, line) {
			t.Errorf("el error debe incluir el número de línea %s, salida: %s", line, out)
		}
	}
}

func TestReadTailWindowBounded(t *testing.T) {
	// Ventana acotada (D7): con un archivo mayor a la ventana solo se lee el
	// final; la primera línea de la ventana (posiblemente cortada) se descarta.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compact := func(id, ip, uri string) string {
		return `{"transaction":{"timestamp":"06/Aug/2026:15:00:00 +0000","unix_timestamp":1786028400,"id":"` + id +
			`","client_ip":"` + ip + `","client_port":1,"host_ip":"10.0.0.5","host_port":443,"server_id":"",` +
			`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"` + uri + `","http_version":"1.1","headers":{},"body":"","files":[],"args":"","length":0},` +
			`"response":null,"producer":null,"highest_severity":"2","is_interrupted":true},"messages":[]}`
	}
	// Línea 1 basura larga (queda fuera de la ventana), línea 2 cortada por el
	// límite de la ventana, líneas 3 y 4 completas dentro de la ventana.
	lineOld := strings.Repeat("x", 300) + "\n"
	lineCut := compact("tx-corte", "9.9.9.9", "/cortada") + "\n"
	lineA := compact("tx-9991", "9.9.9.1", "/ok1") + "\n"
	lineB := compact("tx-9992", "9.9.9.2", "/ok2") + "\n"
	content := lineOld + lineCut + lineA + lineB
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("fallo escribiendo fixture: %v", err)
	}

	// La ventana empieza 40 bytes dentro de lineCut: queda cortada, pero
	// lineA y lineB entran completas.
	prev := maxTailBytes
	maxTailBytes = int64(len(content) - len(lineOld) - 40)
	t.Cleanup(func() { maxTailBytes = prev })

	logs := captureLogs(t)
	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	// Solo las líneas completas de la ventana (tx-9991 y tx-9992).
	if len(got.Entries) != 2 {
		t.Fatalf("la ventana debe devolver solo las líneas completas del final, se obtuvo %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].Client != "9.9.9.2" || got.Entries[1].Client != "9.9.9.1" {
		t.Errorf("orden newest-first esperado 9.9.9.2, 9.9.9.1, se obtuvo %+v", got.Entries)
	}
	// La línea 1 (basura) quedó fuera de la ventana: no debe loguearse ningún
	// error de parseo, ni la línea cortada debe reportarse como error.
	out := logs.String()
	if strings.Contains(out, "no parseable") {
		t.Errorf("la basura fuera de la ventana no debe leerse (lectura acotada), logs: %s", out)
	}
	if strings.Contains(out, "tx-corte") {
		t.Errorf("la línea cortada debe descartarse sin error, logs: %s", out)
	}
}

// pluginAuditJSON arma un objeto en el formato que escribe el plugin
// caddy-waf v3.3.1 (imagen ghcr.io/developmi/caddy-waf): actionset sin lista
// de acciones disruptivas ("OWASP_CRS/4.28.0"), timestamp "YYYY/MM/DD
// HH:MM:SS" (no Apache) y unix_timestamp en nanosegundos.
func pluginAuditJSON(id, ip, uri string) string {
	return `{"transaction":{"timestamp":"2026/08/15 04:06:23","unix_timestamp":1786766783310338248,"id":"` + id +
		`","client_ip":"` + ip + `","client_port":1,"host_ip":"10.0.0.5","host_port":443,"server_id":"",` +
		`"request":{"method":"GET","protocol":"HTTP/1.1","uri":"` + uri + `","http_version":"1.1","headers":{},"body":"","files":[],"args":"","length":0},` +
		`"response":null,"producer":null,"highest_severity":"2","is_interrupted":false},` +
		`"messages":[{"actionset":"OWASP_CRS/4.28.0","message":"Path Traversal Attack (/../) or (/.../)",` +
		`"data":{"id":930100,"msg":"Path Traversal Attack (/../) or (/.../)"}}]}`
}

func TestReadParsesPluginJSONWithoutNewlines(t *testing.T) {
	// El plugin caddy-waf v3.3.1 escribe el audit log como objetos JSON
	// concatenados SIN \n (todo el stream cae en una "línea" y el loop JSONL
	// no puede partirlo): el branch Decoder debe leer el objeto completo.
	dir := t.TempDir()
	path := filepath.Join(dir, "coraza-audit.log")
	content := pluginAuditJSON("sbFfTCoDDhkAiWoq", "172.80.3.1", "/?q=../../etc/passwd")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("fallo escribiendo fixture: %v", err)
	}

	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("se esperaba 1 entrada, se obtuvieron %d: %+v", len(got.Entries), got.Entries)
	}
	e := got.Entries[0]
	if e.Client != "172.80.3.1" {
		t.Errorf("client debe ser 172.80.3.1, se obtuvo %q", e.Client)
	}
	if e.URI != "/?q=../../etc/passwd" {
		t.Errorf("uri debe ser /?q=../../etc/passwd, se obtuvo %q", e.URI)
	}
	if e.RuleID != "930100" {
		t.Errorf("ruleID debe ser 930100, se obtuvo %q", e.RuleID)
	}
	if e.Action != "DETECTED" {
		t.Errorf("sin action ni is_interrupted el default debe ser DETECTED, se obtuvo %q", e.Action)
	}
	if !strings.Contains(e.Message, "Path Traversal") {
		t.Errorf("message debe contener 'Path Traversal', se obtuvo %q", e.Message)
	}
}

func TestReadParsesConcatenatedJSONWithoutNewlines(t *testing.T) {
	// Dos objetos concatenados sin \n (el append del plugin no agrega
	// separadores): deben leerse como dos entradas, newest-first.
	dir := t.TempDir()
	path := filepath.Join(dir, "coraza-audit.log")
	content := pluginAuditJSON("tx-9991", "10.0.0.1", "/a") +
		pluginAuditJSON("tx-9992", "10.0.0.2", "/b")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("fallo escribiendo fixture: %v", err)
	}

	got, err := Read(path, Options{})
	if err != nil {
		t.Fatalf("Read falló: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("se esperaban 2 entradas, se obtuvieron %d: %+v", len(got.Entries), got.Entries)
	}
	if got.Entries[0].Client != "10.0.0.2" || got.Entries[1].Client != "10.0.0.1" {
		t.Errorf("orden newest-first esperado 10.0.0.2, 10.0.0.1, se obtuvo %+v", got.Entries)
	}
	if got.Total != 2 {
		t.Errorf("Total debe ser 2, se obtuvo %d", got.Total)
	}
}

func TestReadMissingFileReturnsError(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "no-existe.log"), Options{}); err == nil {
		t.Fatal("se esperaba error con archivo inexistente")
	}
}

func TestAuditLogPathFromEnvWithDefault(t *testing.T) {
	t.Setenv("CADDY_UI_AUDIT_LOG", "/tmp/audit.log")
	if got := AuditLogPath(); got != "/tmp/audit.log" {
		t.Errorf("AuditLogPath debe leer CADDY_UI_AUDIT_LOG, se obtuvo %q", got)
	}
	t.Setenv("CADDY_UI_AUDIT_LOG", "")
	if got := AuditLogPath(); got != "/data/logs/coraza-audit.log" {
		t.Errorf("sin env el default debe ser /data/logs/coraza-audit.log, se obtuvo %q", got)
	}
}

func TestClassifyActionMapping(t *testing.T) {
	cases := []struct {
		name        string
		txAction    string
		interrupted bool
		actionsets  []string
		want        string
	}{
		{"deny explicito", "deny", false, nil, "BLOCKED"},
		{"drop explicito", "drop", false, nil, "BLOCKED"},
		{"redirect explicito", "redirect", false, nil, "BLOCKED"},
		{"pass explicito", "pass", false, nil, "DETECTED"},
		{"allow explicito", "allow", false, nil, "DETECTED"},
		{"deny en actionset", "", false, []string{"id:942100,phase:2,deny,log"}, "BLOCKED"},
		{"redirect con valor en actionset", "", false, []string{"id:12345,phase:2,redirect:https://x/blocked,log"}, "BLOCKED"},
		{"pass en actionset", "", false, []string{"id:920420,phase:2,pass,log"}, "DETECTED"},
		{"allow en actionset gana a is_interrupted", "", true, []string{"id:910000,phase:1,allow,log"}, "DETECTED"},
		{"sin verbos pero interrumpida", "", true, []string{"id:920000,phase:2,log"}, "BLOCKED"},
		{"sin señales", "", false, nil, "DETECTED"},
		{"action explicito gana a actionset", "deny", false, []string{"id:910000,phase:1,allow,log"}, "BLOCKED"},
	}
	for _, tc := range cases {
		if got := classify(tc.txAction, tc.interrupted, tc.actionsets); got != tc.want {
			t.Errorf("%s: se esperaba %s, se obtuvo %s", tc.name, tc.want, got)
		}
	}
}

func TestPaginatePure(t *testing.T) {
	entries := make([]AuditEntry, 55)
	for i := range entries {
		entries[i] = AuditEntry{RuleID: strconv.Itoa(i)}
	}

	p1 := paginate(entries, 1, 50)
	if len(p1.Entries) != 50 || p1.Total != 55 || p1.Pages != 2 {
		t.Fatalf("página 1: esperadas 50 entradas, Total 55, Pages 2; se obtuvo len=%d Total=%d Pages=%d", len(p1.Entries), p1.Total, p1.Pages)
	}
	p2 := paginate(entries, 2, 50)
	if len(p2.Entries) != 5 {
		t.Fatalf("página 2: se esperaban 5 entradas, se obtuvo %d", len(p2.Entries))
	}
	if p2.Entries[0].RuleID != "50" {
		t.Errorf("la entrada 51 debe ser la de índice 50, se obtuvo %q", p2.Entries[0].RuleID)
	}

	empty := paginate(nil, 1, 50)
	if empty.Entries == nil || len(empty.Entries) != 0 || empty.Page != 1 || empty.Pages != 0 {
		t.Fatalf("lista vacía: Entries no-nil vacío, Page 1, Pages 0; se obtuvo %+v", empty)
	}

	def := paginate(entries, 0, 0)
	if def.Page != 1 || def.PageSize != 50 {
		t.Errorf("page=0/pageSize=0 deben caer a 1/50, se obtuvo page=%d pageSize=%d", def.Page, def.PageSize)
	}
}

func TestParseLineRejectsUnknownFormat(t *testing.T) {
	if _, err := parseLine([]byte("esto no es json")); err == nil {
		t.Error("línea no JSON debe dar error")
	}
	if _, err := parseLine([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("JSON sin transaction.id debe dar error (formato desconocido)")
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	cases := []struct {
		ts   string
		unix int64
		want string
	}{
		{"06/Aug/2026:14:23:11 +0000", 0, "2026-08-06T14:23:11Z"}, // layout Apache de Coraza
		{"", 1786026367, "2026-08-06T14:26:07Z"},                  // fallback unix_timestamp
		{"formato-desconocido", 0, "formato-desconocido"},         // se conserva el valor crudo
		{"", 0, ""}, // sin datos
	}
	for _, tc := range cases {
		if got := normalizeTimestamp(tc.ts, tc.unix); got != tc.want {
			t.Errorf("normalizeTimestamp(%q, %d): se esperaba %q, se obtuvo %q", tc.ts, tc.unix, tc.want, got)
		}
	}
}
