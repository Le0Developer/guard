package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContentSecurityPolicy(t *testing.T) {
	a := &App{}
	css, err := assetPath("styles.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/", http.StatusSeeOther},
		{"GET", css, http.StatusOK},
		{"GET", "/missing", http.StatusNotFound},
		{"POST", "/login", http.StatusForbidden},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			want := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
			if got := w.Header().Get("Content-Security-Policy"); got != want {
				t.Errorf("Content-Security-Policy = %q, want %q", got, want)
			}
		})
	}
}

func TestSAMLContentSecurityPolicyOverride(t *testing.T) {
	for _, action := range []string{"'self'", "https://sp.example.com"} {
		t.Run(action, func(t *testing.T) {
			var nonces []string
			for range 2 {
				w := httptest.NewRecorder()
				(&App{}).middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nonce := samlCSP(w, action)
					nonces = append(nonces, nonce)
					_, _ = w.Write([]byte("ok"))
				})).ServeHTTP(w, httptest.NewRequest("GET", "/saml/test/continue", nil))
				policy := w.Header().Get("Content-Security-Policy")
				for _, directive := range []string{"default-src 'none'", "style-src 'self'", "script-src 'nonce-" + nonces[len(nonces)-1] + "'", "form-action " + action, "base-uri 'none'", "frame-ancestors 'none'"} {
					if !strings.Contains(policy+";", directive+";") {
						t.Errorf("missing %q in %q", directive, policy)
					}
				}
				if strings.Contains(policy, "unsafe-") || len(w.Header().Values("Content-Security-Policy")) != 1 {
					t.Errorf("unexpected SAML policy: %q", policy)
				}
			}
			if nonces[0] == "" || nonces[0] == nonces[1] {
				t.Error("SAML script nonce must be nonempty and unique per response")
			}
		})
	}
}
