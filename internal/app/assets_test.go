package app

import (
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

func TestHashedAssets(t *testing.T) {
	a := &App{}
	for _, name := range []string{"styles.css", "security.js", "provider-setup.js"} {
		content, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		ext := path.Ext(name)
		url := fmt.Sprintf("/static/%s.%x%s", strings.TrimSuffix(name, ext), digest[:6], ext)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != 200 || w.Body.String() != string(content) {
			t.Fatalf("%s: status %d, content matches: %v", url, w.Code, w.Body.String() == string(content))
		}
		if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("cache control: %s", got)
		}
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/static/styles.invalid.css", nil))
	if w.Code != 404 {
		t.Errorf("unknown hash: %d", w.Code)
	}
}

func TestPageAssets(t *testing.T) {
	for _, tc := range []struct{ name, body, script string }{
		{"password", passwordTemplate, ""},
		{"MFA challenge", mfaChallengeTemplate, "security"},
		{"TOTP challenge", mfaChallengeTemplate, ""},
		{"MFA management", mfaManagementTemplate, "security"},
		{"backup codes", backupCodesTemplate, "security"},
		{"provider", adminUpstreamTemplate, "provider-setup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&App{}).page(w, httptest.NewRequest("GET", "/login", nil), "Test", tc.body, map[string]any{"HasKeys": tc.name == "MFA challenge", "Target": map[string]any{}})
			if w.Code != 200 {
				t.Fatalf("render: %d %s", w.Code, w.Body.String())
			}
			html := w.Body.String()
			if strings.Contains(html, "/static/styles.css") || !strings.Contains(html, "/static/styles.") {
				t.Error("stylesheet URL is not hashed")
			}
			for _, script := range []string{"security", "provider-setup"} {
				if got := strings.Contains(html, "/static/"+script+"."); got != (tc.script == script) {
					t.Errorf("%s loaded: %v", script, got)
				}
			}
		})
	}
}
