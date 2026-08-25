package logs

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestParseLevel verifica el mapeo de CADDY_UI_LOG_LEVEL a niveles de slog.
// Los valores válidos (debug/info/warn/error) mapean a su nivel; cualquier
// valor desconocido o vacío cae a info (fail-safe, decisión D1).
func TestParseLevel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"valor inválido", "trace", slog.LevelInfo},
		{"vacío", "", slog.LevelInfo},
	}
	for _, tc := range cases {
		if got := parseLevel(tc.in); got != tc.want {
			t.Errorf("parseLevel(%q): se esperaba %v, se obtuvo %v", tc.in, tc.want, got)
		}
	}
}

// TestSetupHonorsThreshold verifica que Setup() respete el nivel configurado:
// con CADDY_UI_LOG_LEVEL=warn los mensajes debug/info se descartan y los
// warn/error se emiten. Captura la salida redirigiendo os.Stdout a un pipe.
func TestSetupHonorsThreshold(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe falló: %v", err)
	}
	prevStdout := os.Stdout
	prevDefault := slog.Default()
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = prevStdout
		slog.SetDefault(prevDefault)
	})

	t.Setenv("CADDY_UI_LOG_LEVEL", "warn")
	Setup()

	slog.Debug("debug invisible")
	slog.Info("info invisible")
	slog.Warn("warn visible")
	slog.Error("error visible")

	if err := w.Close(); err != nil {
		t.Fatalf("cerrando pipe: %v", err)
	}
	out := make([]byte, 4096)
	n, err := r.Read(out)
	if err != nil {
		t.Fatalf("leyendo pipe: %v", err)
	}
	got := string(out[:n])

	for _, want := range []string{"warn visible", "error visible"} {
		if !strings.Contains(got, want) {
			t.Errorf("se esperaba %q en la salida (nivel warn), salida: %s", want, got)
		}
	}
	for _, banned := range []string{"debug invisible", "info invisible"} {
		if strings.Contains(got, banned) {
			t.Errorf("no debe aparecer %q con threshold warn, salida: %s", banned, got)
		}
	}
}
