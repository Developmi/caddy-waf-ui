package ui

import (
	"net/http"
	"net/url"

	"github.com/developmi/caddy-waf-ui/internal/auth"
	"github.com/developmi/caddy-waf-ui/internal/domain"
	"github.com/developmi/caddy-waf-ui/internal/service"
	"github.com/developmi/caddy-waf-ui/internal/waf"
)

// redirectAfterForm aplica el patrón PRG (spec web-ui): POST + 303 con
// ?flash=, preservando ?tab, ?domain, ?search y ?actionFilter para que la
// vista de origen (y su contexto) sobreviva a la redirección. Un 303 nunca
// reenvía el POST al refrescar.
func redirectAfterForm(w http.ResponseWriter, r *http.Request, flash string) {
	q := url.Values{}
	for _, key := range []string{"tab", "domain", "search", "actionFilter"} {
		if value := r.FormValue(key); value != "" {
			q.Set(key, value)
		}
	}
	q.Set("flash", flash)
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// HandleLogin procesa POST /login (ruta pública): valida el token y fija la
// cookie de sesión (D3). El fallo redirige al login con flash=invalid_login
// (PRG, sin estado mutado).
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if auth.Login(w, r.FormValue("token")) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?flash=invalid_login", http.StatusSeeOther)
}

// HandleLogout procesa POST /logout: invalida la cookie y vuelve al login.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	auth.Logout(w)
	http.Redirect(w, r, "/login?flash=logged_out", http.StatusSeeOther)
}

// HandleFormSetMode procesa POST /sites/{domain}/mode (PRG): delega en la
// cadena compartida (validate → backup → generate → write → reload → audit).
// Un modo inválido devuelve 303 ?flash=error sin mutar nada (el servicio
// valida ANTES del backup).
func HandleFormSetMode(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	mode := domain.WAFMode(r.FormValue("mode"))
	if err := service.UpdateWAFMode(domainName, mode, r.RemoteAddr); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormAddExclusion procesa POST /sites/{domain}/exclusions: fusiona la
// exclusión nueva con las activas (overlay.go) y envía la lista COMPLETA a la
// cadena compartida - que reemplaza el overlay. Sin la fusión, agregar una
// regla borraría silenciosamente las existentes.
func HandleFormAddExclusion(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	exclusion := waf.Exclusion{
		Type:  waf.ExcludeByID,
		Value: r.FormValue("ruleId"),
		Param: r.FormValue("param"),
	}

	current, err := readExclusions(domainName)
	if err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	merged := append(current, exclusion)

	if err := service.UpdateExclusions(domainName, merged, r.RemoteAddr); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormAddIPRule procesa POST /sites/{domain}/iprules: agrega la
// entrada a la lista DENY o ALLOW del estado actual y envía la lista completa
// a la cadena compartida (misma razón de fusión que exclusions).
func HandleFormAddIPRule(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	cidr := r.FormValue("cidr")
	action := r.FormValue("action")

	current, err := readIPRules(domainName)
	if err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	switch action {
	case "DENY":
		current.Denylist = append(current.Denylist, cidr)
	case "ALLOW":
		current.Allowlist = append(current.Allowlist, cidr)
	default:
		redirectAfterForm(w, r, "error")
		return
	}

	if err := service.UpdateIPRules(domainName, current, r.RemoteAddr); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}

// HandleFormRollback procesa POST /sites/{domain}/rollback (PRG, contrato del
// DOM .jinja: domain + snapId): restaura el snapshot indicado (nombre completo
// {ISO8601}.{tipo}.conf) a través de la cadena compartida. El fallo redirige
// con flash=error sin mutar nada (fail-fast de validación en el servicio).
func HandleFormRollback(w http.ResponseWriter, r *http.Request) {
	domainName := r.PathValue("domain")
	backupID := r.FormValue("snapId")

	if err := service.Rollback(domainName, backupID, r.RemoteAddr); err != nil {
		redirectAfterForm(w, r, "error")
		return
	}
	redirectAfterForm(w, r, "success")
}
