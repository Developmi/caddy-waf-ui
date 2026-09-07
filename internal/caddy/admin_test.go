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
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers":
			// Read-back (D3): the live config reflects the host of the submitted Caddyfile.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"srv0":{"routes":[{"match":[{"host":["example.com"]}]}]}}`)
			return
		case r.Method != http.MethodPost:
			t.Errorf("Reload should use POST, but used %s", r.Method)
		case r.URL.Path != "/load":
			t.Errorf("Reload should target /load, but was %s", r.URL.Path)
		}

		if ct := r.Header.Get("Content-Type"); ct != "text/caddyfile" {
			t.Errorf("Content-Type should be text/caddyfile, but was %q", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("could not read the request body: %v", err)
		}

		if string(body) != testCaddyfileContent {
			t.Errorf("the reload body does not match the Caddyfile\nExpected:\n%s\nReceived:\n%s", testCaddyfileContent, string(body))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("CADDY_ADMIN_URL", server.URL)
	t.Setenv("CADDY_UI_CADDYFILE", caddyfilePath)

	if err := caddy.Reload(); err != nil {
		t.Fatalf("Reload failed unexpectedly: %v", err)
	}

	rb := caddy.LastReadback()
	if !rb.OK {
		t.Errorf("read-back should be OK after a successful reload, but was: %+v", rb)
	}
	if rb.Servers != 1 {
		t.Errorf("read-back should report 1 server, but reported %d", rb.Servers)
	}
}

// TestReloadReadbackMismatch verifies the fail-loud (D3): if the live config
// does NOT reflect the hosts of the submitted Caddyfile, Reload returns an
// error so the D6 chain can restore the previous overlay.
func TestReloadReadbackMismatch(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/apps/http/servers" {
			// The live config does NOT contain example.com.
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
		t.Fatal("Reload should fail when the read-back does not find the submitted hosts")
	}
	if !strings.Contains(err.Error(), "read-back") {
		t.Errorf("the error should mention the read-back, but was: %v", err)
	}

	rb := caddy.LastReadback()
	if rb.OK {
		t.Error("the read-back state should be marked as failed on a mismatch")
	}
	if len(rb.Missing) != 1 || rb.Missing[0] != "example.com" {
		t.Errorf("Missing should list example.com, but was: %v", rb.Missing)
	}
}

// TestReloadReadbackUnavailable verifies that an unavailable GET /config
// (network error or non-200 HTTP) also fails loud: the verification cannot be
// confirmed and the state is recorded.
func TestReloadReadbackUnavailable(t *testing.T) {
	caddyfilePath := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(caddyfilePath, []byte(testCaddyfileContent), 0o600); err != nil {
		t.Fatalf("failed to write test Caddyfile: %v", err)
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
		t.Fatal("Reload should fail if the read-back is unavailable")
	}
	if !strings.Contains(err.Error(), "post-reload verification") {
		t.Errorf("the error should mention the post-reload verification, but was: %v", err)
	}

	rb := caddy.LastReadback()
	if rb.OK {
		t.Error("the read-back state should be marked as failed when the verification is unavailable")
	}
}

func TestReloadMissingCaddyfile(t *testing.T) {
	t.Setenv("CADDY_UI_CADDYFILE", filepath.Join(t.TempDir(), "no-existe.conf"))

	err := caddy.Reload()
	if err == nil {
		t.Fatal("Reload should fail if the Caddyfile does not exist, but returned no error")
	}

	if !strings.Contains(err.Error(), "Caddyfile") {
		t.Errorf("the error should mention the Caddyfile, but was: %v", err)
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

// TestReloadDoesNotFollowRedirectOnLoad: if POST /load responds 302, the
// client must NOT follow the redirect: Reload fails (non-200) and the
// redirect target never receives the request.
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

// TestReloadDoesNotFollowRedirectOnReadback: the read-back (D3) GET /config
// also does not follow redirects: Reload fails the verification and the
// redirect target is never requested.
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
	if !strings.Contains(err.Error(), "post-reload verification") {
		t.Errorf("error should mention the post-reload verification, got: %v", err)
	}
	if redirectHits != 0 {
		t.Errorf("redirect target should never be requested, got %d hits", redirectHits)
	}
	if rb := caddy.LastReadback(); rb.OK {
		t.Error("readback state should be marked as failed")
	}
}

// TestReloadReadbackWithRealCaddyfile: a real Caddyfile from the repo
// (global block with email/log/format and sites with header/tls) must not
// confuse Caddy directives with hosts: the read-back (D3) only compares
// hostnames.
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
