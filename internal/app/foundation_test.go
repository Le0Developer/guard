package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigRejectsInsecureDomain(t *testing.T) {
	for _, domain := range []string{"http://example.com", "https://example.com/path", "https://example.com?x=y"} {
		if _, err := configFromEnv(func(k string) string {
			if k == "DOMAIN" {
				return domain
			}
			if k == "DATABASE_URL" {
				return "postgres://localhost/guard"
			}
			return ""
		}); err == nil {
			t.Fatalf("accepted %s", domain)
		}
	}
}
func TestCSRFRejectsForgedForm(t *testing.T) {
	a := &App{Config: Config{Domain: "https://auth.example.com"}, secret: "secret"}
	h := a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("POST", "https://auth.example.com/logout", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
}
func TestUnknownRoutesDoNotRenderHome(t *testing.T) {
	a := &App{Config: Config{Domain: "https://auth.example.com"}}
	w := httptest.NewRecorder()
	a.home(w, httptest.NewRequest("GET", "/missing", nil))
	if w.Code != 404 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestFormPagesPreserveSameOriginForBrowserPosts(t *testing.T) {
	a := &App{Config: Config{Domain: "http://localhost:4444"}, secret: "secret"}
	h := a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost:4444/login/password", nil))
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("form navigation policy %q can produce opaque Origin:null", got)
	}
}
