package ui

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/files"
	"github.com/developmi/caddy-waf-ui/internal/iprules"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// ModeRequest define el cuerpo esperado para cambiar el modo del WAF.
type ModeRequest struct {
	Mode domain.WAFMode `json:"mode"`
}

// ExclusionsRequest define el cuerpo esperado para actualizar exclusiones.
type ExclusionsRequest struct {
	Exclusions []waf.Exclusion `json:"exclusions"`
}

// RollbackRequest define el cuerpo esperado para restaurar un snapshot:
// el nombre completo del backup ("{ISO8601}.{tipo}.conf", contrato D2).
type RollbackRequest struct {
	Backup string `json:"backup"`
}

// maxBodyBytes limita el tamaño de los cuerpos JSON de la API (defensa
// contra DoS por memoria, hallazgo J1): 1 MiB es suficiente para los
// payloads de configuración que gestiona la UI.
const maxBodyBytes = 1 << 20

// decodeJSONBody decodifica el cuerpo JSON de un request con un tope de
// tamaño. Un cuerpo que supera el límite responde 413; cualquier otro error
// de decode responde 400 (mismo estilo de error que los handlers previos).
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Payload demasiado grande", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Payload inválido", http.StatusBadRequest)
		}
		return err
	}
	return nil
}

// clientIP extrae la IP del cliente de r.RemoteAddr (formato host:port) para
// que el campo remote_ip del log de auditoría no arrastre el puerto.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeJSON responde con un JSON plano de confirmación (contrato REST).
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// HandleSetMode cambia el modo del motor WAF de un dominio (RESTful).
// El dominio llega por path param (Go 1.22+ ServeMux) y la cadena compartida
// (validate → backup → generate → write → reload → audit) vive en service.
func HandleSetMode(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req ModeRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := service.UpdateWAFMode(domainName, req.Mode, clientIP(r)); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Dominio inválido", http.StatusBadRequest)
			return
		}
		if errors.Is(err, service.ErrInvalidMode) {
			http.Error(w, "Modo WAF inválido", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error aplicando la configuración", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleSetExclusions actualiza las exclusiones CRS de un dominio (RESTful).
// La validación del payload ocurre ANTES de la cadena (defensa en profundidad:
// la cadena vuelve a validar): un payload inválido es 400, no 500.
func HandleSetExclusions(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req ExclusionsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := waf.ValidateExclusions(req.Exclusions); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := service.UpdateExclusions(domainName, req.Exclusions, clientIP(r)); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Dominio inválido", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error aplicando la configuración", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleSetIPRules actualiza las listas allow/deny de un dominio (RESTful).
// La validación del payload ocurre ANTES de la cadena (defensa en profundidad:
// la cadena vuelve a validar): un payload inválido es 400, no 500.
func HandleSetIPRules(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req iprules.IPRules
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := iprules.ValidateIPRules(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := service.UpdateIPRules(domainName, req, clientIP(r)); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Dominio inválido", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error aplicando la configuración", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}

// HandleListBackups lista los snapshots de configuración de un dominio
// (RESTful, spec backup-recovery). Sin backups responde 200 con [].
func HandleListBackups(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	snapshots, err := files.ListBackups(domainName)
	if err != nil {
		http.Error(w, "Error listando backups", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshots)
}

// HandleRollback restaura un snapshot de configuración de un dominio
// (RESTful): el cuerpo lleva el nombre completo del backup y la cadena
// compartida ejecuta validar → respaldar → restaurar → recargar → auditar.
func HandleRollback(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")

	var req RollbackRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	if err := service.Rollback(domainName, req.Backup, clientIP(r)); err != nil {
		if errors.Is(err, service.ErrInvalidDomain) {
			http.Error(w, "Dominio inválido", http.StatusBadRequest)
			return
		}
		if errors.Is(err, files.ErrInvalidBackup) {
			http.Error(w, "Snapshot de configuración inválido", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error restaurando la configuración", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, `{"status":"success"}`)
}
