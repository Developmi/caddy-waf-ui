package caddy_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/developmi/caddy-waf-ui/internal/caddy"
)

const testCaddyfileContent = `{
	admin localhost:2019
}

example.com {
	import /etc/caddy/ui-managed/ip-rules-example_com.conf
	import /etc/caddy/ui-managed/waf-example_com.conf
}
`

func TestReload(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("no se pudo escribir el Caddyfile de prueba: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers":
			// Read-back (D3): la config viva refleja el host del Caddyfile enviado.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`)
			return
		case r.Method != http.MethodPost:
			t.Errorf("Reload debería usar POST, pero usó %s", r.Method)
		case r.URL.Path != "/load":
			t.Errorf("Reload debería apuntar a /load, pero fue %s", r.URL.Path)
		}

		if ct := r.Header.Get("Content-Type"); ct != "text/caddyfile" {
			t.Errorf("Content-Type debería ser text/caddyfile, pero fue %q", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("no se pudo leer el body del request: %v", err)
		}

		if string(body) != testCaddyfileContent {
			t.Errorf("el body del reload no coincide con el Caddyfile\nEsperado:\n%s\nRecibido:\n%s", testCaddyfileContent, string(body))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	if err := caddy.Reload(); err != nil {
		t.Fatalf("Reload falló inesperadamente: %v", err)
	}

	rb := caddy.LastReadback()
	if !rb.OK {
		t.Errorf("el read-back debería estar OK tras un reload exitoso, pero fue: %+v", rb)
	}
	if rb.Servers != 1 {
		t.Errorf("el read-back debería reportar 1 server, pero reportó %d", rb.Servers)
	}
}

// TestReloadReadbackMismatch verifica el fail-loud (D3): si la config viva NO
// refleja los hosts del Caddyfile enviado, Reload devuelve error para que la
// cadena D6 restaure el overlay previo.
func TestReloadReadbackMismatch(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("no se pudo escribir el Caddyfile de prueba: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			// La config viva NO contiene example.com.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"srv0":{"routes":[{"match":[{"host":["other.com"]}]}]}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload debería fallar cuando el read-back no encuentra los hosts enviados")
	}
	if !strings.Contains(err.Error(), "read-back") {
		t.Errorf("el error debería mencionar el read-back, pero fue: %v", err)
	}

	rb := caddy.LastReadback()
	if rb.OK {
		t.Error("el estado de read-back debería marcar fallo en un mismatch")
	}
	if len(rb.Missing) != 1 || rb.Missing[0] != "example.com" {
		t.Errorf("Missing debería listar example.com, pero fue: %v", rb.Missing)
	}
}

// TestReloadReadbackUnavailable verifica que un GET /config no disponible
// (error de red o HTTP no-200) también falla loud: la verificación no puede
// confirmarse y el estado queda registrado.
func TestReloadReadbackUnavailable(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("no se pudo escribir el Caddyfile de prueba: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload debería fallar si el read-back no está disponible")
	}
	if !strings.Contains(err.Error(), "verificación post-reload") {
		t.Errorf("el error debería mencionar la verificación post-reload, pero fue: %v", err)
	}

	rb := caddy.LastReadback()
	if rb.OK {
		t.Error("el estado de read-back debería marcar fallo cuando la verificación no está disponible")
	}
}

func TestReloadMissingCaddyfile(t *testing.T) {
	t.Setenv("CADDY_UI_CADDYFILE", filepath.Join(t.TempDir(), "no-existe.conf"))

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload debería fallar si el Caddyfile no existe, pero no devolvió error")
	}

	if !strings.Contains(err.Error(), "Caddyfile") {
		t.Errorf("el error debería mencionar el Caddyfile, pero fue: %v", err)
	}
}

func TestReloadRejectsInvalidAdminURL(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	for _, tt := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "invalid scheme", raw: "ftp://caddy-waf:2019", wantErr: "scheme must be http or https"},
		{name: "empty host", raw: "http://", wantErr: "host must not be empty"},
		{name: "userinfo", raw: "http://admin:secret@caddy-waf:2019", wantErr: "userinfo is not allowed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CADDY_ADMIN_URL", tt.raw)
			t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

			err := caddy.Reload()
			if err == nil {
				t.Fatal("Reload should fail-loud when CADDY_ADMIN_URL is invalid")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error should mention %q, got: %v", tt.wantErr, err)
			}
			rb := caddy.LastReadback()
			if rb.OK {
				t.Error("readback state should be marked as failed")
			}
		})
	}
}

// TestReloadDoesNotFollowRedirectOnLoad: si POST /load responde 302, el
// cliente NO debe seguir la redirección: Reload falla (no-200) y el destino
// del redirect nunca recibe el request.
func TestReloadDoesNotFollowRedirectOnLoad(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	redirectHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-target" {
			redirectHits++
		}
		w.Header().Set("Location", "/redirect-target")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload should fail when POST /load returns 302")
	}
	if !strings.Contains(err.Error(), "HTTP 302") {
		t.Errorf("error should surface the 302 status, got: %v", err)
	}
	if redirectHits != 0 {
		t.Errorf("redirect target should never be requested, got %d hits", redirectHits)
	}
	if rb := caddy.LastReadback(); rb.OK {
		t.Error("readback state should be marked as failed")
	}
}

// TestReloadDoesNotFollowRedirectOnReadback: el GET /config del read-back
// (D3) tampoco sigue redirecciones: Reload falla en la verificación y el
// destino del redirect nunca se pide.
func TestReloadDoesNotFollowRedirectOnReadback(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	redirectHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			w.WriteHeader(http.StatusOK) // load ok; the redirect happens on read-back
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers":
			w.Header().Set("Location", "/redirect-target")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/redirect-target":
			redirectHits++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload should fail when the read-back GET /config redirects")
	}
	if !strings.Contains(err.Error(), "verificación post-reload") {
		t.Errorf("error should mention the post-reload verification, got: %v", err)
	}
	if redirectHits != 0 {
		t.Errorf("redirect target should never be requested, got %d hits", redirectHits)
	}
	if rb := caddy.LastReadback(); rb.OK {
		t.Error("readback state should be marked as failed")
	}
}

// TestReloadReadbackWithRealCaddyfile: un Caddyfile real del repo (bloque
// global con email/log/format y sitios con header/tls) no debe confundir las
// directivas de Caddy con hosts: el read-back (D3) solo compara hostnames.
func TestReloadReadbackWithRealCaddyfile(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	caddyfile := `{
    admin 0.0.0.0:2019
    email {$ACME_EMAIL}
    order coraza_waf first
    log {
        output stdout
        format json {
            time_format "iso8601"
        }
    }
}

example.localhost {
    import waf
    tls internal
    header {
        X-Content-Type-Options "nosniff"
    }
    respond "ok" 200
}

api.localhost {
    tls {
        protocols tls1.2 tls1.3
    }
    header {
        X-Frame-Options "DENY"
    }
    reverse_proxy example-app:80
}
`
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"srv0":{"routes":[{"match":[{"host":["example.localhost"]}]},{"match":[{"host":["api.localhost"]}]}]}}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	if err := caddy.Reload(); err != nil {
		t.Fatalf("Reload should succeed with a real Caddyfile, got: %v", err)
	}
	rb := caddy.LastReadback()
	if !rb.OK {
		t.Errorf("readback should be OK, got: %+v", rb)
	}
}
