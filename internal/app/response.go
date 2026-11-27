package app

import (
	"bytes"
	"net/http"
)

// bufferedResponse holds credentials and redirects until their required journal write succeeds.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse    { return &bufferedResponse{header: make(http.Header)} }
func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(p)
}
func (b *bufferedResponse) flush(w http.ResponseWriter) {
	for name, values := range b.header {
		w.Header()[name] = values
	}
	status := b.status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}
func journalUnavailable(w http.ResponseWriter) {
	// A failed required write must never expose identity, credentials or a redirect.
	if b, ok := w.(*bufferedResponse); ok {
		b.header = make(http.Header)
		b.status = 0
		b.body.Reset()
	}
	for _, name := range []string{"Location", "Set-Cookie", "X-Guard-User-Id", "X-Guard-Username"} {
		w.Header().Del(name)
	}
	jsonResponse(w, 503, map[string]string{"error": "access_journal_unavailable"})
}
