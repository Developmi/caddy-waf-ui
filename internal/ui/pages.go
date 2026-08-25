package ui

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/caddy"
	"github.com/developmi/caddy-waf-ui/internal/config"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/logs"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// managedDir devuelve el directorio de overlays gestionados. Centralizado en
// config (hallazgo J5-3): la lectura de entorno vivía triplicada en
// internal/service, internal/files y este paquete.
func managedDir() string {
	return config.ManagedDir()
}

// crsRule describe una entrada del catálogo fijo de reglas CRS con falsos
// positivos conocidos. El catálogo está hardcodeado (6 reglas) y sin
// simulate-attack ni AI (eliminados del producto).
type crsRule struct {
	RuleID      string
	Category    string
	Name        string
	Description string
}

// crsCatalog es el catálogo de reglas CRS que la UI ofrece como exclusiones
// de un clic, con su descripción pública (UI copy en inglés).
var crsCatalog = []crsRule{
	{RuleID: "942100", Category: "SQLi", Name: "SQL Injection Detected via libinjection", Description: "Detects classic SQL injection payloads in request values."},
	{RuleID: "941100", Category: "XSS", Name: "XSS Attack Detected via libinjection", Description: "Detects cross-site scripting payloads in request values."},
	{RuleID: "930120", Category: "LFI", Name: "OS File Access Attempt", Description: "Detects path traversal attempts that read local files."},
	{RuleID: "920420", Category: "Protocol", Name: "Request Content Type Is Not Allowed by Policy", Description: "Rejects request content types outside the configured policy."},
	{RuleID: "932100", Category: "RCE", Name: "Remote Command Execution: Windows Command Injection", Description: "Detects Windows command injection attempts."},
	{RuleID: "942200", Category: "SQLi", Name: "SQL Injection: MySQL Comment/Space Obfuscation", Description: "Detects MySQL comment/space obfuscated injection attempts."},
}

// pageData es el modelo de datos común a todas las páginas SSR. Cada
// plantilla consume solo los campos que necesita; las vistas cuyos datos
// provienen de fases posteriores (logs, snapshots) llegan como estado vacío
// honesto con el shape ya definido en el diseño (AuditEntry, BackupInfo).
type pageData struct {
	ActiveTab        string
	Flash            string
	FlashType        string
	CSRF             string
	Sites            []*domain.Site
	CurrentSite      *domain.Site
	SitesOn          int
	SitesDetection   int
	TotalExclusions  int
	TotalIPRules     int
	TotalDenyIPs     int
	TotalAllowIPs    int
	Logs             []logs.AuditEntry
	LogSearch        string
	ActionFilter     string
	LogPage          int
	LogPages         int
	LogPrevURL       string
	LogNextURL       string
	CRSCatalog       []crsRule
	ActiveExclusions []waf.Exclusion
	ExclusionsConf   string
	ActiveIPRules    iprules.IPRules
	IPRulesConf      string
	Snapshots        []files.BackupInfo
	WafConf          string
	Readback         caddy.ReadbackState
}

// flashMessage traduce la clave ?flash= a un mensaje visible (UI copy en
// inglés; los mensajes HTTP fuera del HTML siguen en español por convención).
func flashMessage(key string) string {
	switch key {
	case "success":
		return "Configuration updated successfully."
	case "error":
		return "The configuration could not be applied. Check the service logs for details."
	case "invalid_login":
		return "Invalid access token."
	case "logged_out":
		return "You have been signed out."
	default:
		return key
	}
}

// flashType mapea la clave del flash al tipo visual del toast (fix J3-1):
// error → variante roja con role="alert" y aria-live="assertive"; el resto
// se presenta como éxito/info verde con role="status" y aria-live="polite".
func flashType(key string) string {
	if key == "error" {
		return "error"
	}
	return "success"
}

// flashCookie transporta el flash entre el redirect de consumo (one-shot) y
// el render de la página: la URL queda limpia y un refresh no re-muestra el
// toast viejo. La cookie es efímera (60s), HttpOnly + SameSite=Lax.
const flashCookieName = "ui_flash"

// setFlashCookie fija la cookie efímera del flash para el hop de consumo
// (misma convención de flags que la cookie de sesión: HttpOnly + Secure).
func setFlashCookie(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    key,
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeFlashCookie lee la cookie del flash y la borra (one-shot: se consume en
// el primer render; un refresh posterior no la re-muestra).
func takeFlashCookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return "", false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return cookie.Value, true
}

// cleanURL devuelve la misma ruta sin el parámetro ?flash= (one-shot: el
// toast se consume con un redirect limpio; la cookie transporta el mensaje).
// Preserva tab/domain/search/actionFilter/page para que el contexto de la
// vista sobreviva al hop.
func cleanURL(q url.Values) string {
	clean := url.Values{}
	for _, key := range []string{"tab", "domain", "search", "actionFilter", "page"} {
		if value := q.Get(key); value != "" {
			clean.Set(key, value)
		}
	}
	if len(clean) == 0 {
		return "/"
	}
	return "/?" + clean.Encode()
}

// scanSites escanea los sitios descubiertos en ui-managed (scanner, D2:
// lectura por request) y los devuelve ordenados por dominio. El Registry en
// memoria fue eliminado (hallazgo J5-6): la abstracción se creaba y
// descartaba por request sin aportar estado compartido.
func scanSites() []*domain.Site {
	scanner := domain.NewScanner(managedDir())
	sites, err := scanner.Scan()
	if err != nil {
		slog.Warn("error escaneando overlays", "error", err)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites
}

// findSite ubica el sitio seleccionado por ?domain=; sin match (o sin sitios)
// usa el primero de la lista para que las vistas con selector no queden vacías.
func findSite(sites []*domain.Site, domainName string) *domain.Site {
	for _, site := range sites {
		if site.Domain == domainName {
			return site
		}
	}
	if len(sites) > 0 {
		return sites[0]
	}
	return nil
}

// readOverlay devuelve el contenido actual de un overlay ("" si no existe).
// Es el estado desplegado real, la fuente de verdad para los previews.
func readOverlay(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("error leyendo overlay", "path", path, "error", err)
		}
		return ""
	}
	return string(content)
}

// countOverlays recorre los overlays de exclusiones y reglas IP de TODOS los
// dominios para las métricas del overview (las vistas por dominio usan los
// parsers de overlay.go).
func countOverlays() (exclusions, ipRules, deny, allow int) {
	entries, err := os.ReadDir(managedDir())
	if err != nil {
		return 0, 0, 0, 0
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(managedDir(), name)
		switch {
		case strings.HasPrefix(name, files.FileTypeExclusions+"-") && strings.HasSuffix(name, ".conf"):
			if ex, err := readExclusionsFile(path); err == nil {
				exclusions += len(ex)
			}
		case strings.HasPrefix(name, files.FileTypeIPRules+"-") && strings.HasSuffix(name, ".conf"):
			if rules, err := readIPRulesFile(path); err == nil {
				ipRules += len(rules.Denylist) + len(rules.Allowlist)
				deny += len(rules.Denylist)
				allow += len(rules.Allowlist)
			}
		}
	}
	return exclusions, ipRules, deny, allow
}

// csrfOrEmpty deriva el token CSRF para los formularios; si el token no está
// configurado devuelve "" (el middleware de sesión ya bloquea todo acceso).
func csrfOrEmpty() string {
	token, err := auth.CSRFValue()
	if err != nil {
		return ""
	}
	return token
}

// logPageURL arma la URL de una página del explorador de logs preservando los
// filtros activos (tab/search/actionFilter). page < 1 devuelve "" para que el
// template no renderice el enlace (fuera de rango).
func logPageURL(q url.Values, page int) string {
	if page < 1 {
		return ""
	}
	query := url.Values{}
	query.Set("tab", "logs")
	if search := q.Get("search"); search != "" {
		query.Set("search", search)
	}
	if action := q.Get("actionFilter"); action != "" {
		query.Set("actionFilter", action)
	}
	query.Set("page", strconv.Itoa(page))
	return "/?" + query.Encode()
}

// loadLogs lee la página solicitada del audit log de Coraza (D7) con los
// filtros de la query string. Si el archivo aún no existe (primer arranque)
// se registra un warn y la tabla queda en estado vacío honesto.
func loadLogs(q url.Values) (logs.Page, bool) {
	page, _ := strconv.Atoi(q.Get("page"))
	result, err := logs.Read(logs.AuditLogPath(), logs.Options{
		Search: q.Get("search"),
		Action: q.Get("actionFilter"),
		Page:   page,
	})
	if err != nil {
		slog.Warn("no se pudo leer el audit log", "path", logs.AuditLogPath(), "error", err)
		return logs.Page{}, false
	}
	return result, true
}

// buildPageData arma el modelo de datos de la página activa. La vista logs
// se alimenta del audit log real (Fase 3); rollback sigue en estado vacío
// honesto (lectura en Fase 4).
func buildPageData(r *http.Request, tab string, sites []*domain.Site) pageData {
	q := r.URL.Query()
	data := pageData{
		ActiveTab:    tab,
		Flash:        flashMessage(q.Get("flash")),
		FlashType:    flashType(q.Get("flash")),
		CSRF:         csrfOrEmpty(),
		Sites:        sites,
		LogSearch:    q.Get("search"),
		ActionFilter: q.Get("actionFilter"),
		CRSCatalog:   crsCatalog,
		Logs:         []logs.AuditEntry{},
		Snapshots:    []files.BackupInfo{},
	}

	if tab == "logs" {
		if result, ok := loadLogs(q); ok {
			data.Logs = result.Entries
			data.LogPage = result.Page
			data.LogPages = result.Pages
			data.LogPrevURL = logPageURL(q, result.Page-1)
			data.LogNextURL = logPageURL(q, result.Page+1)
		}
	}

	data.CurrentSite = findSite(sites, q.Get("domain"))
	if data.CurrentSite != nil {
		domainName := data.CurrentSite.Domain
		data.WafConf = readOverlay(files.WAFConfigPath(managedDir(), domainName))
		data.ExclusionsConf = readOverlay(files.ExclusionsConfigPath(managedDir(), domainName))
		data.IPRulesConf = readOverlay(files.IPRulesConfigPath(managedDir(), domainName))
		if ex, err := readExclusions(domainName); err == nil {
			data.ActiveExclusions = ex
		}
		if rules, err := readIPRules(domainName); err == nil {
			data.ActiveIPRules = rules
		}
	}

	// El tab rollback se alimenta de los snapshots REALES del dominio (Fase 4);
	// sin backups (o directorio inexistente) queda el estado vacío honesto.
	if tab == "rollback" && data.CurrentSite != nil {
		snapshots, err := files.ListBackups(data.CurrentSite.Domain)
		if err != nil {
			slog.Warn("no se pudieron listar los snapshots", "domain", data.CurrentSite.Domain, "error", err)
		} else {
			data.Snapshots = snapshots
		}
	}

	for _, site := range sites {
		switch site.Mode {
		case domain.ModeOn:
			data.SitesOn++
		case domain.ModeDetectionOnly:
			data.SitesDetection++
		}
	}
	data.TotalExclusions, data.TotalIPRules, data.TotalDenyIPs, data.TotalAllowIPs = countOverlays()
	data.Readback = caddy.LastReadback()
	return data
}

// executePage ejecuta la plantilla base de la página indicada (todas las
// plantillas definen el bloque "base"; las páginas de contenido, además,
// definen "content").
func executePage(w http.ResponseWriter, page string, data pageData) error {
	tmpl, ok := templates[page]
	if !ok {
		return fmt.Errorf("plantilla desconocida: %s", page)
	}
	return tmpl.ExecuteTemplate(w, "base", data)
}

// HandleIndex renderiza la página activa según ?tab (SSR; spec web-ui:
// página renderiza 200, sin errores de template, escapado automático).
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}

	// Flash one-shot (fix J3-12): el ?flash= del PRG se consume con un
	// redirect limpio que transporta el mensaje en una cookie efímera; un
	// refresh de la URL limpia no re-muestra el toast.
	if key := r.URL.Query().Get("flash"); key != "" {
		setFlashCookie(w, key)
		http.Redirect(w, r, cleanURL(r.URL.Query()), http.StatusFound)
		return
	}

	data := buildPageData(r, tab, scanSites())
	if key, ok := takeFlashCookie(w, r); ok {
		data.Flash = flashMessage(key)
		data.FlashType = flashType(key)
	}
	if err := executePage(w, tab, data); err != nil {
		slog.Error("error renderizando página", "tab", tab, "error", err)
		http.Error(w, "Error interno renderizando la página", http.StatusInternalServerError)
	}
}

// HandleLoginPage renderiza el formulario de login (ruta pública). Si ya hay
// sesión válida, redirige al índice. El flash (?flash= o cookie) recibe el
// mismo tratamiento one-shot que el índice.
func HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.HasValidSession(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if key := r.URL.Query().Get("flash"); key != "" {
		setFlashCookie(w, key)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := pageData{}
	if key, ok := takeFlashCookie(w, r); ok {
		data.Flash = flashMessage(key)
		data.FlashType = flashType(key)
	}
	if err := executePage(w, "login", data); err != nil {
		slog.Error("error renderizando login", "error", err)
		http.Error(w, "Error interno renderizando la página", http.StatusInternalServerError)
	}
}

// NewPagesMux ensambla las rutas SSR protegidas por sesión (cookie o Bearer).
// Las mutaciones se montan bajo /sites/{domain}/... y pasan por el middleware
// CSRF en cmd/server/main.go (task 2.7).
func NewPagesMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", HandleIndex)
	mux.HandleFunc("POST /sites/{domain}/mode", HandleFormSetMode)
	mux.HandleFunc("POST /sites/{domain}/exclusions", HandleFormAddExclusion)
	mux.HandleFunc("POST /sites/{domain}/iprules", HandleFormAddIPRule)
	mux.HandleFunc("POST /sites/{domain}/rollback", HandleFormRollback)
	mux.HandleFunc("POST /logout", HandleLogout)
	return mux
}

// NewLoginMux expone las rutas públicas de autenticación (sin sesión).
func NewLoginMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", HandleLoginPage)
	mux.HandleFunc("POST /login", HandleLogin)
	return mux
}
