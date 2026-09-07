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

// ReadbackState describes the latest post-reload verification result (D3):
// after each POST /load, the UI queries Caddy's live config
// (GET /config/apps/http/servers) to confirm that the submitted Caddyfile
// was actually adopted - closing the "blind 200" gap that only trusted the
// load response.
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

// LastReadback returns the latest recorded verification state. The UI exposes
// it as a badge/flag (same pattern as the scanner's Degraded flag).
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

// siteHostRE captures the literal hosts of the Caddyfile's site blocks.
// By design it does NOT capture: the global block ("{"), snippets ("(waf) {"),
// comments, or environment-variable addresses ("{$SITE_ADDRESS}").
var siteHostRE = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9*.-]+(?::\d+)?(?:\s*,\s*[a-zA-Z0-9*.-]+(?::\d+)?)*)\s*\{`)

// looksLikeHost filters out tokens that are not hosts: Caddy directives such
// as "email {...}", "log {", "header {" or "format json {" match the capture
// regex because they end in "{", but they are not hostnames. A real host is
// an FQDN (contains "."), a port address (contains ":") or "localhost".
func looksLikeHost(h string) bool {
	return strings.Contains(h, ".") || strings.Contains(h, ":") || h == "localhost"
}

// expectedHosts extracts the literal host names of a Caddyfile. Port-only
// addresses (":80") are discarded: they live in listen addresses, not host
// matchers, and cannot be verified against /config/apps/http/servers.
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

// validateAdminURL validates the Admin API URL (CADDY_ADMIN_URL): http/https
// scheme, host present, and no userinfo. The Admin API does not accept
// embedded credentials, and a failure must be loud BEFORE issuing any
// request, so configuration errors are not hidden behind network failures.
func validateAdminURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid CADDY_ADMIN_URL: %w", err)
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

// newAdminClient returns an HTTP client for the Admin API with a fixed
// timeout and no redirect following: a 30x is never a valid admin result,
// and following it could dispatch the load/read to a destination other than
// the configured one (fail-loud on the raw response).
func newAdminClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fetchLiveHosts queries the live config and collects the hosts of the
// server blocks ("host" matchers of the HTTP routes). It also returns the
// number of loaded servers.
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
		return nil, 0, fmt.Errorf("GET /config/apps/http/servers returned %s", resp.Status)
	}

	var cfg any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&cfg); err != nil {
		return nil, 0, fmt.Errorf("unparseable /config response: %w", err)
	}

	var hosts []string
	servers := 0
	if m, ok := cfg.(map[string]any); ok {
		servers = len(m)
	}
	collectHosts(cfg, &hosts)
	return hosts, servers, nil
}

// collectHosts walks the config JSON recursively and accumulates the values
// of Caddy's "host" matchers (HTTP routes).
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

// Reload reads the Caddyfile (configured via CADDY_UI_CADDYFILE) and sends
// it to POST /load on Caddy's Admin API with Content-Type text/caddyfile.
// This lets Caddy re-adapt the imports and take the updated ui-managed/
// snippets into effect. On any failure (unreadable file or rejected reload)
// it returns an explicit error (fail-loud).
//
// D3 (read-back): after a 200 from the load, it queries the live config and
// verifies that the literal hosts of the submitted Caddyfile are present in
// the host matchers. If the verification fails, Reload returns an error so
// that the D6 chain in the service layer can restore the previous overlay.
// Note: on a read-back failure the config was already applied by Caddy; the
// overlay restoration is flagged in the ReadbackState and in the audit log.
func Reload() error {
	// Centralized in config (finding J5-3): environment reads no longer live
	// in this package.
	adminURL := config.AdminURL()
	if err := validateAdminURL(adminURL); err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return err
	}

	caddyfilePath := config.CaddyfilePath()

	caddyfile, err := os.ReadFile(caddyfilePath)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("could not read Caddyfile %q: %w", caddyfilePath, err)
	}

	req, err := http.NewRequest(http.MethodPost, adminURL+"/load", bytes.NewReader(caddyfile))
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error creating reload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	client := newAdminClient()
	loadResp, err := client.Do(req)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("error performing reload in Caddy: %w", err)
	}
	defer func() { _ = loadResp.Body.Close() }()

	if loadResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loadResp.Body)
		msg := fmt.Sprintf("caddy POST /load failed with HTTP %d: %s", loadResp.StatusCode, string(body))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: msg})
		return errors.New(msg)
	}

	// Read-back (D3): the live config must reflect the submitted hosts.
	live, servers, err := fetchLiveHosts(adminURL)
	if err != nil {
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Err: err.Error()})
		return fmt.Errorf("post-reload verification failed: %w", err)
	}

	var missing []string
	for _, h := range expectedHosts(caddyfile) {
		if !containsHost(live, h) {
			missing = append(missing, h)
		}
	}

	if len(missing) > 0 {
		msg := fmt.Sprintf("read-back: hosts not found in the live config: %s", strings.Join(missing, ", "))
		setReadback(ReadbackState{OK: false, CheckedAt: time.Now().UTC(), Servers: servers, Missing: missing, Err: msg})
		return errors.New(msg)
	}

	setReadback(ReadbackState{OK: true, CheckedAt: time.Now().UTC(), Servers: servers})
	return nil
}
