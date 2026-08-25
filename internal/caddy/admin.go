package caddy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// ReadbackState describe el último resultado de la verificación post-reload
// (D3): tras cada POST /load, la UI consulta la config viva de Caddy
// (GET /config/apps/http/servers) para confirmar que el Caddyfile enviado fue
// realmente adoptado - cierra el gap del "200 ciego" que solo confiaba en la
// respuesta del load.
type ReadbackState struct {
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at"`
	Servers   int       `json:"servers"`
	Missing   []string  `json:"missing,omitempty"`
	Err       string    `json:"err,omitempty"`
}

var (
	readbackMu   sync.Mutex
	lastReadback ReadbackState
)

// LastReadback devuelve el último estado de verificación registrado. La UI lo
// expone como badge/flag (mismo patrón que el flag Degraded del scanner).
func LastReadback() ReadbackState {
	readbackMu.Lock()
	defer readbackMu.Unlock()
	return lastReadback
}

func setReadback(s ReadbackState) {
	readbackMu.Lock()
	lastReadback = s
	readbackMu.Unlock()
}

// siteHostRE captura los hosts literales de los bloques de sitio del Caddyfile.
// Por diseño NO captura: el bloque global ("{"), los snippets ("(waf) {"), los
// comentarios ni las direcciones con variable de entorno ("{$SITE_ADDRESS}").
var siteHostRE = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9*.-]+(?::\d+)?(?:\s*,\s*[a-zA-Z0-9*.-]+(?::\d+)?)*)\s*\{`)

// looksLikeHost filtra tokens que no son hosts: directivas de Caddy como
// "email {...}", "log {", "header {" o "format json {" matchean la regex de
// captura porque terminan en "{", pero no son hostnames. Un host real es un
// FQDN (contiene "."), una dirección con puerto (contiene ":") o "localhost".
func looksLikeHost(h string) bool {
	return strings.Contains(h, ".") || strings.Contains(h, ":") || h == "localhost"
}

// expectedHosts extrae los nombres de host literales de un Caddyfile. Las
// direcciones solo-puerto (":80") se descartan: viven en listen addresses, no
// en host matchers, y no son verificables contra /config/apps/http/servers.
func expectedHosts(caddyfile []byte) []string {
	var hosts []string
	seen := make(map[string]bool)
	for _, m := range siteHostRE.FindAllSubmatch(caddyfile, -1) {
		for _, part := range strings.Split(string(m[1]), ",") {
			h := strings.TrimSpace(part)
			if h == "" || strings.HasPrefix(h, ":") || seen[h] || !looksLikeHost(h) {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// validateAdminURL valida la URL de la Admin API (CADDY_ADMIN_URL): scheme
// http/https, host presente y sin userinfo. La Admin API no admite
// credenciales embebidas y el fallo debe ser loud ANTES de emitir cualquier
// request, para no ocultar errores de configuración detrás de fallos de red.
func validateAdminURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("CADDY_ADMIN_URL inválido: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("CADDY_ADMIN_URL: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("CADDY_ADMIN_URL: host must not be empty")
	}
	if u.User != nil {
		return fmt.Errorf("CADDY_ADMIN_URL: userinfo is not allowed")
	}
	return nil
}

// newAdminClient devuelve un cliente HTTP para la Admin API con timeout fijo
// y sin seguir redirecciones: un 30x nunca es un resultado válido del admin y
// seguirlo podría despachar la carga/lectura hacia un destino distinto del
// configurado (fail-loud sobre la respuesta bruta).
func newAdminClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetchLiveHosts consulta la config viva y recolecta los hosts de los server
// blocks (matchers "host" de las rutas HTTP). Devuelve además la cantidad de
// servers cargados.
func fetchLiveHosts(adminURL string) ([]string, int, error) {
	if err := validateAdminURL(adminURL); err != nil {
		return nil, 0, err
	}
	client := newAdminClient()
	resp, err := client.Get(adminURL + "/config/apps/http/servers")
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("GET /config/apps/http/servers devolvió %s", resp.Status)
	}

	var cfg any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&cfg); err != nil {
		return nil, 0, fmt.Errorf("respuesta /config no parseable: %w", err)
	}

	var hosts []string
	servers := 0
	if m, ok := cfg.(map[string]any); ok {
		servers = len(m)
	}
	collectHosts(cfg, &hosts)
	return hosts, servers, nil
}

// collectHosts camina el JSON de config recursivamente y acumula los valores
// de los matchers "host" de Caddy (rutas HTTP).
func collectHosts(v any, hosts *[]string) {
	switch t := v.(type) {
	case map[string]any:
		if h, ok := t["host"]; ok {
			if arr, ok := h.([]any); ok {
				for _, e := range arr {
					if s, ok := e.(string); ok {
						*hosts = append(*hosts, s)
					}
				}
			}
		}
		for _, val := range t {
			collectHosts(val, hosts)
		}
	case []any:
		for _, val := range t {
			collectHosts(val, hosts)
		}
	}
}

func containsHost(live []string, h string) bool {
	for _, l := range live {
		if l == h {
			return true
		}
	}
	return false
}

// Reload lee el Caddyfile (configurado en CADDY_UI_CADDYFILE) y lo envía a
// POST /load en la Admin API de Caddy con Content-Type text/caddyfile.
// Así Caddy re-adapta los imports y los snippets actualizados de ui-managed/
// surten efecto. Ante cualquier fallo (archivo ilegible o recarga rechazada)
// devuelve un error explícito (fail-loud).
//
// D3 (read-back): tras un 200 del load, consulta la config viva y verifica que
// los hosts literales del Caddyfile enviado estén en los host matchers. Si la
// verificación falla, Reload devuelve error para que la cadena D6 del service
// layer restaure el overlay previo. Nota: en el fallo de read-back la config ya
// fue aplicada por Caddy; la restauración del overlay queda señalada en el
// estado ReadbackState y en el log de auditoría.
func Reload() error {
	// Centralizado en config (hallazgo J5-3): las lecturas de entorno ya no
	// viven en este paquete.
	adminURL := config.AdminURL()
	if err := validateAdminURL(adminURL); err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return err
	}

	caddyfilePath := config.CaddyfilePath()

	caddyfile, err := os.ReadFile(caddyfilePath)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("no se pudo leer el Caddyfile %q: %w", caddyfilePath, err)
	}

	req, err := http.NewRequest(http.MethodPost, adminURL+"/load", bytes.NewReader(caddyfile))
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error creando request de recarga: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	client := newAdminClient()
	loadResp, err := client.Do(req)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error ejecutando recarga en Caddy: %w", err)
	}
	defer func() { _ = loadResp.Body.Close() }()

	if loadResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loadResp.Body)
		msg := fmt.Sprintf("caddy POST /load falló con HTTP %d: %s", loadResp.StatusCode, string(body))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: msg})
		return errors.New(msg)
	}

	// Read-back (D3): la config viva debe reflejar los hosts enviados.
	live, servers, err := fetchLiveHosts(adminURL)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("verificación post-reload falló: %w", err)
	}

	var missing []string
	for _, h := range expectedHosts(caddyfile) {
		if !containsHost(live, h) {
			missing = append(missing, h)
		}
	}

	if len(missing) > 0 {
		msg := fmt.Sprintf("read-back: hosts no encontrados en la config viva: %s", strings.Join(missing, ", "))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Servers: servers, Missing: missing, Err: msg})
		return errors.New(msg)
	}

	setReadback(ReadbackState{OK: true, CheckedAt: time.Now().UTC(), Servers: servers})
	return nil
}
