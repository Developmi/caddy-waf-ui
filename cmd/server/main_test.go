package main

import (
	"net/http"
	"testing"
	"time"
)

// TestNewServerBounds (SH-1): the newServer constructor must set the four
// HTTP server limits: ReadHeaderTimeout 5s (slowloris, G114; kept),
// WriteTimeout 30s (covers the 2x10s Caddy admin chain), IdleTimeout 60s
// (margin over the 30s healthcheck) and MaxHeaderBytes 1 MiB. It must also
// propagate as-is the listening address and the assembled handler (it does
// not assemble muxes: that stays in main()).
func TestNewServerBounds(t *testing.T) {
	addr := "127.0.0.1:18099"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := newServer(addr, handler)

	if srv.Addr != addr {
		t.Errorf("Addr: expected %q, got %q", addr, srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("Handler: it cannot be nil, it must propagate the received handler")
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout: expected 5s, got %v", srv.ReadHeaderTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout: expected 30s, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout: expected 60s, got %v", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes: expected 1 MiB (%d), got %d", 1<<20, srv.MaxHeaderBytes)
	}
}
