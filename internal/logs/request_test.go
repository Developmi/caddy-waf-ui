package logs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequestLoggerEmitsExactlyOneUIRequest verifies the AU-12 scenario: an
// authenticated request that completes produces exactly one ui_request entry
// with method, path, remote_ip and status, and the response reaches the
// client intact (body and status passthrough).
func TestRequestLoggerEmitsExactlyOneUIRequest(t *testing.T) {
	logs := captureLogs(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(RequestLogger(inner))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/sites/example.com")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Passthrough: the client receives the status and body of the inner handler.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("passthrough: expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("passthrough: expected body %q, got %q", "ok", string(body))
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("expected exactly 1 ui_request entry, got %d", got)
	}
	for _, want := range []string{"method=GET", "path=/sites/example.com", "remote_ip=127.0.0.1", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("the ui_request entry must contain %s, output: %s", want, out)
		}
	}
}

// TestRequestLoggerRecordsNon2xxStatus verifies the AU-12 scenario of a
// non-2xx status: a 404 from the inner handler is recorded with its real
// status and the client also receives the 404 (passthrough).
func TestRequestLoggerRecordsNon2xxStatus(t *testing.T) {
	logs := captureLogs(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(RequestLogger(inner))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/missing")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("passthrough: expected 404, got %d", resp.StatusCode)
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("expected exactly 1 ui_request entry, got %d", got)
	}
	if !strings.Contains(out, "status=404") {
		t.Errorf("the real status (404) must be recorded, output: %s", out)
	}
	if !strings.Contains(out, "path=/missing") {
		t.Errorf("the entry must record the real path, output: %s", out)
	}
}
