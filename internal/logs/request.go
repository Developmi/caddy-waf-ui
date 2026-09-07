package logs

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// statusRecorder wraps an http.ResponseWriter to capture the real status
// code without altering the response the client receives (passthrough).
// The status is available after the inner handler responds.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the code and forwards it to the original writer.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards the flush to the original writer if it implements http.Flusher
// (e.g. SSE streaming when it lands in the project).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards the connection to the original writer if it implements
// http.Hijacker (WebSockets); if it does not, it returns ErrNotSupported.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

// ReadFrom forwards the direct copy to the original writer if it implements
// io.ReaderFrom (io.Copy optimization for large responses); the fallback
// copies via Write.
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{r.ResponseWriter}, src)
}

// RequestLogger records each authenticated request as a ui_request entry
// (NIST AU-12) with method, path, remote_ip and status, reusing LogRequest.
//
// It is placed INSIDE authentication (Session/Middleware) and OUTSIDE CSRF:
// only authenticated requests are logged, and CSRF rejections (403) are also
// recorded (decision D2).
//
// The optional interfaces of the original writer (http.Flusher, http.Hijacker
// and io.ReaderFrom) are forwarded to avoid degrading flows such as SSE or
// WebSockets if any handler uses them (finding J1).
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		LogRequest(r.Method, r.URL.Path, r.RemoteAddr, rec.status)
	})
}
