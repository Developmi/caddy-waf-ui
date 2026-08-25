package logs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequestLoggerEmitsExactlyOneUIRequest verifica el escenario AU-12:
// un request autenticado que completa produce exactamente una entrada
// ui_request con method, path, remote_ip y status, y la respuesta llega
// intacta al cliente (passthrough de body y status).
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
		t.Fatalf("GET falló: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Passthrough: el cliente recibe el status y el body del handler interno.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("passthrough: se esperaba 200, se obtuvo %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("leyendo body: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("passthrough: se esperaba body %q, se obtuvo %q", "ok", string(body))
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("se esperaba exactamente 1 entrada ui_request, se obtuvieron %d", got)
	}
	for _, want := range []string{"method=GET", "path=/sites/example.com", "remote_ip=127.0.0.1", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("la entrada ui_request debe contener %s, salida: %s", want, out)
		}
	}
}

// TestRequestLoggerRecordsNon2xxStatus verifica el escenario AU-12 de status
// no-2xx: un 404 del handler interno se registra con su status real y el
// cliente también recibe el 404 (passthrough).
func TestRequestLoggerRecordsNon2xxStatus(t *testing.T) {
	logs := captureLogs(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(RequestLogger(inner))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/missing")
	if err != nil {
		t.Fatalf("GET falló: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("passthrough: se esperaba 404, se obtuvo %d", resp.StatusCode)
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("se esperaba exactamente 1 entrada ui_request, se obtuvieron %d", got)
	}
	if !strings.Contains(out, "status=404") {
		t.Errorf("el status real (404) debe registrarse, salida: %s", out)
	}
	if !strings.Contains(out, "path=/missing") {
		t.Errorf("la entrada debe registrar el path real, salida: %s", out)
	}
}
