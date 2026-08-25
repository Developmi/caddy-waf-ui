package logs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// Acciones normalizadas que consume la UI (D7): la plantilla logs.html solo
// conoce BLOCKED/DETECTED.
const (
	actionBlocked  = "BLOCKED"
	actionDetected = "DETECTED"
)

// defaultPageSize es el tamaño de página por defecto del explorador (D7).
const defaultPageSize = 50

// maxTailBytes acota la ventana de lectura a los últimos 2 MiB del audit log
// (D7): nunca se lee el archivo completo. Es una variable para que los tests
// puedan achicarla sin generar fixtures enormes.
var maxTailBytes int64 = 2 << 20

// layoutApache es el formato de timestamp del audit log de Coraza
// ("02/Jan/2006:15:04:20 -0700", ver internal/auditlog/auditlog.go).
const layoutApache = "02/Jan/2006:15:04:05 -0700"

// Options controla el filtrado y la paginación de Read.
type Options struct {
	Search   string // búsqueda case-insensitive sobre client/uri/ruleID/message
	Action   string // "BLOCKED", "DETECTED" o "" (todos)
	Page     int    // 1-based; valores <= 0 se tratan como 1
	PageSize int    // <= 0 → defaultPageSize (50)
}

// Page es una página de entradas más el contexto de paginación.
type Page struct {
	Entries  []AuditEntry
	Page     int
	PageSize int
	Total    int
	Pages    int
}

// AuditLogPath devuelve la ruta configurada del audit log de Coraza
// (CADDY_UI_AUDIT_LOG; default /data/logs/coraza-audit.log - D7). El valor
// vive centralizado en config (hallazgo J5-3); esta función se conserva como
// delegado para no romper los call sites que la usan como API del paquete.
func AuditLogPath() string {
	return config.AuditLogPath()
}

// Read lee la ventana final (2 MiB) del audit log de Coraza, parsea los
// registros, filtra por search/action y pagina el resultado (más recientes
// primero). Soporta dos formatos: JSONL con newlines (el loop de ReadBytes)
// y objetos JSON concatenados SIN newlines (el plugin caddy-waf v3.3.1 hace
// append sin "\n"; json.Decoder los lee de a uno). Un registro que no parsea
// se registra con slog.Error (spec audit-logs: nunca se descarta en
// silencio) y la lectura continúa con el resto.
func Read(path string, opts Options) (Page, error) {
	f, err := os.Open(path)
	if err != nil {
		return Page{}, err
	}
	defer func() { _ = f.Close() }()

	data, err := tailWindow(f)
	if err != nil {
		return Page{}, err
	}

	entries := make([]AuditEntry, 0, 64)
	if bytes.IndexByte(data, '\n') < 0 && len(bytes.TrimSpace(data)) > 0 {
		// Stream sin newlines (plugin caddy-waf v3.3.1): objetos JSON
		// concatenados, un objeto por transacción detectada.
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var l auditLine
			err := dec.Decode(&l)
			if err == io.EOF {
				break
			}
			if err != nil {
				// Fail-loud: tras un error de decode no se puede volver a
				// sincronizar el límite entre objetos; se loguea y se corta.
				slog.Error("audit log sin newlines no parseable", "path", path, "error", err)
				break
			}
			entry, perr := entryFromLine(l)
			if perr != nil {
				// Fail-loud: formato desconocido nunca se ignora.
				slog.Error("entrada no parseable del audit log", "path", path, "error", perr)
				continue
			}
			if matches(entry, opts.Search, opts.Action) {
				entries = append(entries, entry)
			}
		}
	} else {
		// JSONL plano: una entrada por línea.
		reader := bufio.NewReader(bytes.NewReader(data))
		lineNum := 0
		for {
			line, err := reader.ReadBytes('\n')
			lineNum++
			if len(bytes.TrimSpace(line)) > 0 {
				entry, perr := parseLine(line)
				if perr != nil {
					// Fail-loud: formato desconocido nunca se ignora.
					slog.Error("línea no parseable del audit log", "path", path, "line", lineNum, "error", perr)
				} else if matches(entry, opts.Search, opts.Action) {
					entries = append(entries, entry)
				}
			}
			if err != nil {
				if err != io.EOF {
					return Page{}, err
				}
				break
			}
		}
	}

	// El log crece hacia el final: lo más reciente primero.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return paginate(entries, opts.Page, opts.PageSize), nil
}

// tailWindow devuelve los últimos maxTailBytes del archivo. Si el archivo es
// más chico se lee completo; si la ventana corta una línea por la mitad, la
// primera línea de la ventana se descarta (puede estar incompleta; lo
// reciente, que vive al final, queda intacto).
func tailWindow(f *os.File) ([]byte, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() <= maxTailBytes {
		return io.ReadAll(f)
	}
	offset := stat.Size() - maxTailBytes
	buf := make([]byte, maxTailBytes)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	return buf, nil
}

// auditLine es la forma JSON de una entrada del audit log de Coraza
// (formats_json.go de coraza v3). El campo transaction.action no lo emite
// coraza v3 (la acción vive en los actionsets y en is_interrupted), pero se
// acepta por compatibilidad con formatos legacy o escritores de terceros.
type auditLine struct {
	Transaction auditTransaction `json:"transaction"`
	Messages    []auditMessage   `json:"messages"`
}

type auditTransaction struct {
	Timestamp     string `json:"timestamp"`
	UnixTimestamp int64  `json:"unix_timestamp"`
	ID            string `json:"id"`
	ClientIP      string `json:"client_ip"`
	IsInterrupted bool   `json:"is_interrupted"`
	Action        string `json:"action"`
	Request       *struct {
		URI string `json:"uri"`
	} `json:"request"`
}

type auditMessage struct {
	Message   string        `json:"message"`
	Actionset string        `json:"actionset"`
	Data      *auditMsgData `json:"data"`
}

type auditMsgData struct {
	ID  int    `json:"id"`
	Msg string `json:"msg"`
}

// entryFromLine mapea una auditLine ya deserializada a AuditEntry. Sin
// transaction.id devuelve error: el lector lo registra (fail-loud). Es el
// mapeo compartido por parseLine (JSONL) y el branch Decoder del stream sin
// newlines del plugin caddy-waf v3.3.1.
func entryFromLine(l auditLine) (AuditEntry, error) {
	if l.Transaction.ID == "" {
		return AuditEntry{}, fmt.Errorf("línea sin transaction.id (formato desconocido)")
	}

	entry := AuditEntry{
		Timestamp: normalizeTimestamp(l.Transaction.Timestamp, l.Transaction.UnixTimestamp),
		Client:    l.Transaction.ClientIP,
		Action:    classify(l.Transaction.Action, l.Transaction.IsInterrupted, actionsetsOf(l.Messages)),
	}
	if l.Transaction.Request != nil {
		entry.URI = l.Transaction.Request.URI
	}
	for _, m := range l.Messages {
		if entry.Message == "" {
			entry.Message = m.Message
		}
		if entry.RuleID == "" && m.Data != nil && m.Data.ID > 0 {
			entry.RuleID = strconv.Itoa(m.Data.ID)
		}
	}
	return entry, nil
}

// parseLine convierte una línea JSONL a AuditEntry. Cualquier forma que no
// sea una entrada de Coraza (JSON inválido o sin transaction.id) devuelve
// error: el lector lo registra con el número de línea (fail-loud).
func parseLine(raw []byte) (AuditEntry, error) {
	var l auditLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return AuditEntry{}, err
	}
	return entryFromLine(l)
}

// actionsetsOf extrae los actionsets de los mensajes para la clasificación
// de la acción disruptiva (D7: deny/drop/redirect → BLOCKED; pass/allow →
// DETECTED).
func actionsetsOf(messages []auditMessage) []string {
	sets := make([]string, 0, len(messages))
	for _, m := range messages {
		sets = append(sets, m.Actionset)
	}
	return sets
}

// classify determina la acción normalizada de una entrada. Prioridad: campo
// action explícito (legacy) > verbos disruptivos en los actionsets >
// is_interrupted > DETECTED por defecto. allow se considera DETECTED aunque
// interrumpa el procesamiento (D7: pass/allow → DETECTED).
func classify(txAction string, interrupted bool, actionsets []string) string {
	switch strings.ToLower(strings.TrimSpace(txAction)) {
	case "deny", "drop", "redirect":
		return actionBlocked
	case "pass", "allow":
		return actionDetected
	}
	for _, set := range actionsets {
		switch disruptiveVerb(set) {
		case "deny", "drop", "redirect":
			return actionBlocked
		case "pass", "allow":
			return actionDetected
		}
	}
	if interrupted {
		return actionBlocked
	}
	return actionDetected
}

// disruptiveVerb devuelve el primer verbo de acción disruptiva de un
// actionset de Coraza (lista de acciones separadas por comas), o "".
// redirect admite valor ("redirect:https://..."), el resto son verbos sueltos.
func disruptiveVerb(actionset string) string {
	for _, token := range strings.Split(actionset, ",") {
		token = strings.Trim(strings.TrimSpace(token), "'\"")
		switch {
		case token == "deny" || token == "drop" || token == "redirect" || strings.HasPrefix(token, "redirect:"):
			return "deny"
		case token == "pass" || token == "allow":
			return "pass"
		}
	}
	return ""
}

// matches decide si una entrada pasa los filtros: action exacta
// (case-insensitive) y search como substring case-insensitive sobre
// client/uri/ruleID/message.
func matches(e AuditEntry, search, action string) bool {
	if action != "" && !strings.EqualFold(e.Action, action) {
		return false
	}
	search = strings.TrimSpace(search)
	if search == "" {
		return true
	}
	needle := strings.ToLower(search)
	for _, hay := range []string{e.Client, e.URI, e.RuleID, e.Message} {
		if strings.Contains(strings.ToLower(hay), needle) {
			return true
		}
	}
	return false
}

// paginate corta la lista filtrada según page/pageSize (1-based) y devuelve
// el contexto de paginación. Páginas fuera de rango se recortan a la última;
// Entries nunca es nil (el template usa {{ if .Logs }}).
func paginate(entries []AuditEntry, page, pageSize int) Page {
	if entries == nil {
		entries = []AuditEntry{}
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	total := len(entries)
	pages := 0
	if total > 0 {
		pages = (total + pageSize - 1) / pageSize
	}
	if page > pages {
		page = pages
	}
	if page < 1 {
		page = 1
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	return Page{Entries: entries[start:end], Page: page, PageSize: pageSize, Total: total, Pages: pages}
}

// normalizeTimestamp convierte el timestamp de Coraza (formato Apache) a
// RFC3339 para que el helper date de las plantillas pueda formatearlo; si no
// se reconoce, conserva el valor crudo. Sin timestamp usa unix_timestamp.
func normalizeTimestamp(ts string, unix int64) string {
	if ts != "" {
		if parsed, err := time.Parse(layoutApache, ts); err == nil {
			return parsed.Format(time.RFC3339)
		}
		return ts
	}
	if unix > 0 {
		return time.Unix(unix, 0).UTC().Format(time.RFC3339)
	}
	return ts
}
