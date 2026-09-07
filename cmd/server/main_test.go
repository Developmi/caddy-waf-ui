package main

import (
	"net/http"
	"testing"
	"time"
)

// TestNewServerBounds (SH-1): el helper de construcción newServer debe fijar
// los cuatro límites del servidor HTTP: ReadHeaderTimeout 5s (slowloris, G114;
// se mantiene), WriteTimeout 30s (cubre la cadena admin de Caddy de 2x10s),
// IdleTimeout 60s (margen sobre el healthcheck de 30s) y MaxHeaderBytes 1 MiB.
// Además debe propagar tal cual la dirección de escucha y el handler armado
// (no ensambla muxes: eso sigue en main()).
func TestNewServerBounds(t *testing.T) {
	addr := "127.0.0.1:18099"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := newServer(addr, handler)

	if srv.Addr != addr {
		t.Errorf("Addr: se esperaba %q, se obtuvo %q", addr, srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("Handler: no puede ser nil, debe propagar el handler recibido")
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout: se esperaba 5s, se obtuvo %v", srv.ReadHeaderTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout: se esperaba 30s, se obtuvo %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout: se esperaba 60s, se obtuvo %v", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes: se esperaba 1 MiB (%d), se obtuvo %d", 1<<20, srv.MaxHeaderBytes)
	}
}
