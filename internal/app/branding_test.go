package app

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBranding(t *testing.T) {
	icon := filepath.Join(t.TempDir(), "icon.svg")
	content := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>`
	if err := os.WriteFile(icon, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	for _, custom := range []bool{false, true} {
		env := map[string]string{"DOMAIN": "https://auth.example.com", "DATABASE_URL": "postgres://localhost/guard"}
		if custom {
			env["BRAND_NAME"] = "Work <Portal>"
			env["BRAND_ICON_FILE"] = icon
		}
		c, err := configFromEnv(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		a := &App{Config: c}
		w := httptest.NewRecorder()
		a.page(w, httptest.NewRequest("GET", "/login", nil), "Sign in", "", nil)
		name := "Guard"
		if custom {
			name = "Work &lt;Portal&gt;"
		}
		if !strings.Contains(w.Body.String(), "Sign in · "+name) || !strings.Contains(w.Body.String(), "<strong>"+name+"</strong>") {
			t.Errorf("branding missing: %s", w.Body.String())
		}
		if strings.Contains(w.Body.String(), `rel="icon"`) != custom {
			t.Error("unexpected favicon state")
		}
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/branding/icon", nil))
		if custom {
			if w.Code != 200 || w.Body.String() != content || w.Header().Get("Content-Type") != "image/svg+xml" {
				t.Fatalf("icon: %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		} else if w.Code != 404 {
			t.Errorf("unconfigured icon: %d", w.Code)
		}
	}
}

func TestBrandingRejectsInvalidFile(t *testing.T) {
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.png"), t.TempDir()} {
		env := map[string]string{"DOMAIN": "https://auth.example.com", "DATABASE_URL": "postgres://localhost/guard", "BRAND_ICON_FILE": path}
		if _, err := configFromEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "BRAND_ICON_FILE") {
			t.Errorf("expected icon error for %q, got %v", path, err)
		}
	}
}
