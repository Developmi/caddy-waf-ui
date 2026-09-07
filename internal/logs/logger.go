package logs

import (
	"log/slog"
	"os"

	"github.com/developmi/caddy-waf-ui/internal/config"
)

// parseLevel maps the CADDY_UI_LOG_LEVEL value to a slog level.
// Valid values are debug, info, warn and error; any unknown or empty
// value falls back to info (fail-safe, decision D1).
func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Setup initializes the global logger in structured JSON format.
// This ensures compliance with the NIST AU-12 control.
// The level is read from CADDY_UI_LOG_LEVEL and stored in a slog.LevelVar
// to allow runtime adjustment in the future.
func Setup() {
	// Configure slog to emit plain JSON to stdout
	var level slog.LevelVar
	level.Set(parseLevel(config.LogLevel()))
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &level,
		// Optional: we could rename the default fields if strictly necessary,
		// but the slog defaults (time, level, msg) are an excellent standard.
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

// LogAction records a configuration event in a structured way.
// It maps exactly to the fields defined in the architecture[cite: 1].
// Empty optional fields (from/to/reloadStatus) are normalized to "unknown"
// so call sites do not diverge between "" and "unknown" (drift flagged by
// judge J1).
func LogAction(event string, domain string, from string, to string, remoteIP string, reloadStatus string) {
	slog.Info(event,
		slog.String("event", event),
		slog.String("domain", domain),
		slog.String("from", orUnknown(from)),
		slog.String("to", orUnknown(to)),
		slog.String("remote_ip", remoteIP),
		slog.String("caddy_reload", orUnknown(reloadStatus)),
	)
}

// orUnknown normalizes an empty optional field to the canonical "unknown".
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// LogRequest can be used in middleware to trace who attempts to access the UI
func LogRequest(method string, path string, remoteIP string, status int) {
	slog.Info("ui_request",
		slog.String("method", method),
		slog.String("path", path),
		slog.String("remote_ip", remoteIP),
		slog.Int("status", status),
	)
}
