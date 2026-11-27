package app

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
)

func TestRestoredPagesRenderFormsAndNavigation(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	actor := db.User{ID: 1, Username: "alice", Role: "Admin", CreatedAt: now}
	cases := []struct {
		name, path, title, body string
		data                    any
		signedIn                bool
		want                    []string
	}{
		{"provider-discovery", "/admin/providers/new", "Upstream provider", adminUpstreamTemplate, map[string]any{"New": true, "Action": "/admin/providers", "Target": db.UpstreamProvider{ConfigurationMode: "oidc_discovery", ClientAuthMethod: "client_secret_post", SigningAlg: "RS256", Scopes: "openid email", Pkce: true, Enabled: true}, "Algorithms": []string{"RS256"}}, true, []string{"OIDC configuration URL", "configuration JSON document", `name="configuration_mode"`, `value="oauth2"`}},
		{"provider-oauth2", "/admin/providers/new", "Upstream provider", adminUpstreamTemplate, map[string]any{"New": true, "Action": "/admin/providers", "Target": db.UpstreamProvider{ConfigurationMode: "oauth2", ClientAuthMethod: "client_secret_basic", SubjectField: "account.id", EmailField: "emails.0.address", EmailVerifiedField: "emails.0.verified", Scopes: "profile email", Pkce: true, Enabled: true}, "Algorithms": []string{"RS256"}}, true, []string{"Profile field mapping", `value="account.id"`, `value="emails.0.address"`}},
		{"home", "/", "My account", homeTemplate, map[string]any{"Account": actor, "Preview": userinfoPreview{Clients: []userinfoPreviewClient{{ID: "matrix", Name: "Matrix", Selected: true}}, Scope: "openid profile email groups", JSON: "{\n  \"sub\": \"wRtigkpx_gLJd64XsPnKcLAXuevT70QDK7p_jtlZ2AQ\",\n  \"username\": \"alice\"\n}"}, "Apps": []launcherApp{{Name: "Wiki", URL: "https://wiki.example.com"}, {Name: "Staff Portal", URL: "https://portal.example.com"}, {Name: "App without link"}}}, true, []string{"App launcher", `href="https://wiki.example.com"`, `aria-disabled="true"`, "Welcome, alice"}},
		{"login", "/login/password", "Sign in", passwordTemplate, map[string]any{"Login": db.LoginSession{InternalToken: "login-token"}}, false, []string{`placeholder="Your username"`, `name="login_token" value="login-token"`, `class="btn btn-info"`, `autocomplete="current-password"`}},
		{"users", "/admin/users", "Users", adminListTemplate, map[string]any{"Section": "users", "Rows": []adminRow{{ID: "2", Name: "<script>alert(1)</script>", Role: "User", Disabled: true, LocalPassword: true}}}, true, []string{`role="search"`, `class="badge badge-warning"`, `&lt;script&gt;`, `Edit user`, `aria-current="page"`}},
		{"groups", "/admin/groups", "Groups", adminListTemplate, map[string]any{"Section": "groups", "Rows": []adminRow{{ID: "3", Name: "Staff", Count: 4}}}, true, []string{`Members`, `<td>4</td>`, `Edit group`}},
		{"clients", "/admin/clients", "Clients", adminListTemplate, map[string]any{"Section": "clients", "Rows": []adminRow{{ID: "4", Name: "Wiki", Identifier: "wiki", Kind: "Oidc"}}}, true, []string{`<code>wiki</code>`, `OpenID Connect`, `Edit client`}},
		{"security", "/security", "Security · alice", mfaManagementTemplate, map[string]any{"Name": "alice", "Base": "/security", "Count": 8, "Methods": []map[string]any{{"ID": 1, "Kind": "totp", "Name": "Phone", "CreatedAt": now, "LastUsed": nil}}}, true, []string{`<summary>Rename</summary>`, `name="confirm" value="generate" required`, `name="csrf_token" value="test-csrf"`, `/security/methods/totp/1/remove`, `Never`}},
		{"mfa", "/login/mfa", "Verify sign-in", mfaChallengeTemplate, map[string]any{"HasTOTP": true, "HasKeys": true}, false, []string{`name="method" value="recovery"`, `class="btn btn-info"`, `data-webauthn="authenticate"`, `name="csrf_token" value="test-csrf"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			ctx := context.WithValue(r.Context(), csrfKey{}, "test-csrf")
			if tc.signedIn {
				ctx = context.WithValue(ctx, identityKey{}, &identity{User: actor})
			}
			w := httptest.NewRecorder()
			(&App{}).page(w, r.WithContext(ctx), tc.title, tc.body, tc.data)
			if w.Code != 200 {
				t.Fatalf("render failed: %d %s", w.Code, w.Body.String())
			}
			html := w.Body.String()
			if strings.Contains(html, `name="client_auth_method"`) {
				t.Error("client authentication option must not be shown")
			}
			if strings.HasPrefix(tc.path, "/admin/providers") && strings.Contains(html, `name="signing_alg"`) {
				t.Error("provider form still exposes algorithm selection")
			}
			if strings.HasPrefix(tc.path, "/admin/") {
				tag := regexp.MustCompile(`<a[^>]*href="/admin/[^"/]+/new"[^>]*>`).FindString(html)
				if tag != "" && (strings.Count(tag, `class="`) != 1 || !strings.Contains(tag, `class="btn btn-info"`)) {
					t.Errorf("create link must have one button class attribute: %s", tag)
				}
			}

			for _, want := range tc.want {
				if !strings.Contains(html, want) {
					t.Errorf("missing %q", want)
				}
			}
			if strings.Contains(html, "<script>alert(1)</script>") {
				t.Fatal("unescaped user content")
			}
			if strings.HasPrefix(tc.path, "/admin") && strings.Index(html, `aria-label="Administration"`) > strings.Index(html, "<h1>") {
				t.Error("admin navigation must precede page heading")
			}
			if dir := os.Getenv("GUARD_UI_PREVIEW_DIR"); dir != "" {
				if err := os.WriteFile(filepath.Join(dir, tc.name+".html"), w.Body.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
