package domain

import "time"

// WAFMode define los estados permitidos para el motor de Coraza en un sitio específico.
type WAFMode string

const (
	ModeDetectionOnly WAFMode = "DetectionOnly"
	ModeOn            WAFMode = "On"
	ModeOff           WAFMode = "Off"
)

// Site define la entidad principal que gestiona la UI en memoria.
type Site struct {
	Domain  string    `json:"domain"`
	Mode    WAFMode   `json:"mode"`
	Updated time.Time `json:"updated"`

	// Degraded indica que la cabecera del overlay traía un modo desconocido:
	// la UI muestra DetectionOnly (default no-bloqueante, forward-compat) pero
	// ese NO es el estado real cargado en Caddy. El badge "degraded" advierte
	// la desincronización en lugar de ocultarla (W1 verify).
	Degraded bool `json:"degraded"`

	// Nota: Las exclusiones y las reglas de IP se agregarán aquí como structs
	// a medida que implementemos esos módulos, para mantenerlo iterativo.
}
