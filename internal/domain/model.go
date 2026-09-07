package domain

import "time"

// WAFMode defines the allowed states for the Coraza engine on a specific site.
type WAFMode string

const (
	ModeDetectionOnly WAFMode = "DetectionOnly"
	ModeOn            WAFMode = "On"
	ModeOff           WAFMode = "Off"
)

// Site defines the main entity that the UI manages in memory.
type Site struct {
	Domain  string    `json:"domain"`
	Mode    WAFMode   `json:"mode"`
	Updated time.Time `json:"updated"`

	// Degraded indicates that the overlay header carried an unknown mode:
	// the UI shows DetectionOnly (non-blocking default, forward-compat) but
	// that is NOT the real state loaded in Caddy. The "degraded" badge
	// surfaces the desynchronization instead of hiding it (W1 verify).
	Degraded bool `json:"degraded"`

	// Note: Exclusions and IP rules will be added here as structs as we
	// implement those modules, to keep it iterative.
}
