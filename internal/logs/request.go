package logs

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// statusRecorder envuelve un http.ResponseWriter para capturar el código de
// estado real sin alterar la respuesta que recibe el cliente (passthrough).
// El status queda disponible después de que el handler interno responda.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader registra el código y lo reenvía al writer original.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush reenvía el flush al writer original si implementa http.Flusher
// (p.ej. streaming SSE cuando aterrice en el proyecto).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack reenvía la conexión al writer original si implementa http.Hijacker
// (WebSockets); si no lo implementa, devuelve ErrNotSupported.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

// ReadFrom reenvía la copia directa al writer original si implementa
// io.ReaderFrom (optimización de io.Copy para respuestas grandes); el
// fallback copia vía Write.
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{r.ResponseWriter}, src)
}

// RequestLogger registra cada request autenticado como una entrada ui_request
// (NIST AU-12) con method, path, remote_ip y status, reutilizando LogRequest.
//
// Se coloca DENTRO de la autenticación (Session/Middleware) y FUERA de CSRF:
// así solo los requests autenticados se loguean, y los rechazos CSRF (403)
// también quedan registrados (decisión D2).
//
// Las interfaces opcionales del writer original (http.Flusher, http.Hijacker
// e io.ReaderFrom) se reenvían para no degradar flujos como SSE o WebSockets
// si algún handler los usa (hallazgo J1).
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		LogRequest(r.Method, r.URL.Path, r.RemoteAddr, rec.status)
	})
}
