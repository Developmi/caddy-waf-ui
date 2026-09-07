package logs

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestParseLevel verifies the mapping of CADDY_UI_LOG_LEVEL to slog levels.
// Valid values (debug/info/warn/error) map to their level; any unknown or
// empty value falls back to info (fail-safe, decision D1).
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
		{"invalid value", "trace", slog.LevelInfo},
		{"empty", "", slog.LevelInfo},
	}
	for _, tc := range cases {
		if got := parseLevel(tc.in); got != tc.want {
			t.Errorf("parseLevel(%q): expected %v, got %v", tc.in, tc.want, got)
		}
	}
}

// TestSetupHonorsThreshold verifies that Setup() honors the configured level:
// with CADDY_UI_LOG_LEVEL=warn the debug/info messages are dropped and the
// warn/error ones are emitted. It captures the output by redirecting os.Stdout
// to a pipe.
func TestSetupHonorsThreshold(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
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
		t.Fatalf("closing pipe: %v", err)
	}
	out := make([]byte, 4096)
	n, err := r.Read(out)
	if err != nil {
		t.Fatalf("reading pipe: %v", err)
	}
	got := string(out[:n])

	for _, want := range []string{"warn visible", "error visible"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the output (warn level), output: %s", want, got)
		}
	}
	for _, banned := range []string{"debug invisible", "info invisible"} {
		if strings.Contains(got, banned) {
			t.Errorf("%q must not appear with a warn threshold, output: %s", banned, got)
		}
	}
}
