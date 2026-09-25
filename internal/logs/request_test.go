package logs

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequestLoggerEmitsExactlyOneUIRequest verifies the AU-12 scenario: an
// authenticated request that completes produces exactly one ui_request entry
// with method, path, remote_ip and status, and the response reaches the
// client intact (body and status passthrough).
func TestRequestLoggerEmitsExactlyOneUIRequest(t *testing.T) {
	logs := captureLogs(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(RequestLogger(inner))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/sites/example.com")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Passthrough: the client receives the status and body of the inner handler.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("passthrough: expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("passthrough: expected body %q, got %q", "ok", string(body))
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("expected exactly 1 ui_request entry, got %d", got)
	}
	for _, want := range []string{"method=GET", "path=/sites/example.com", "remote_ip=127.0.0.1", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("the ui_request entry must contain %s, output: %s", want, out)
		}
	}
}

// TestRequestLoggerRecordsNon2xxStatus verifies the AU-12 scenario of a
// non-2xx status: a 404 from the inner handler is recorded with its real
// status and the client also receives the 404 (passthrough).
func TestRequestLoggerRecordsNon2xxStatus(t *testing.T) {
	logs := captureLogs(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(RequestLogger(inner))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/missing")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("passthrough: expected 404, got %d", resp.StatusCode)
	}

	out := logs.String()
	if got := strings.Count(out, "ui_request"); got != 1 {
		t.Errorf("expected exactly 1 ui_request entry, got %d", got)
	}
	if !strings.Contains(out, "status=404") {
		t.Errorf("the real status (404) must be recorded, output: %s", out)
	}
	if !strings.Contains(out, "path=/missing") {
		t.Errorf("the entry must record the real path, output: %s", out)
	}
}

type stubFlusherWriter struct {
	http.ResponseWriter
	flushed bool
}

func (s *stubFlusherWriter) Flush() {
	s.flushed = true
}

type stubHijackerWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (s *stubHijackerWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.hijacked = true
	return nil, nil, nil
}

type stubReaderFromWriter struct {
	http.ResponseWriter
	readFromCalled bool
}

func (s *stubReaderFromWriter) ReadFrom(r io.Reader) (int64, error) {
	s.readFromCalled = true
	return io.Copy(io.Discard, r)
}

func TestStatusRecorderFlush(t *testing.T) {
	recPlain := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	recPlain.Flush() // Should not panic when ResponseWriter is not Flusher

	stub := &stubFlusherWriter{ResponseWriter: httptest.NewRecorder()}
	recFlusher := &statusRecorder{ResponseWriter: stub}
	recFlusher.Flush()
	if !stub.flushed {
		t.Errorf("expected Flush() to be delegated to Flusher")
	}
}

func TestStatusRecorderHijack(t *testing.T) {
	recPlain := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	_, _, err := recPlain.Hijack()
	if err != http.ErrNotSupported {
		t.Errorf("expected ErrNotSupported, got %v", err)
	}

	stub := &stubHijackerWriter{ResponseWriter: httptest.NewRecorder()}
	recHijack := &statusRecorder{ResponseWriter: stub}
	_, _, err = recHijack.Hijack()
	if err != nil {
		t.Fatalf("unexpected hijack error: %v", err)
	}
	if !stub.hijacked {
		t.Errorf("expected Hijack() to be delegated to Hijacker")
	}
}

func TestStatusRecorderReadFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec}
	payload := "streaming body content"
	n, err := sr.ReadFrom(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != int64(len(payload)) || rec.Body.String() != payload {
		t.Errorf("ReadFrom copied %d bytes with content %q; expected %d and %q", n, rec.Body.String(), len(payload), payload)
	}

	stub := &stubReaderFromWriter{ResponseWriter: httptest.NewRecorder()}
	srStub := &statusRecorder{ResponseWriter: stub}
	_, err = srStub.ReadFrom(strings.NewReader("sample"))
	if err != nil {
		t.Fatalf("ReadFrom stub failed: %v", err)
	}
	if !stub.readFromCalled {
		t.Errorf("expected ReadFrom() to be delegated to ReaderFrom")
	}
}
