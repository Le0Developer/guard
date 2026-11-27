package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
)

func TestAdminUpstreamAuthorization(t *testing.T) {
	for _, path := range []string{"/admin/providers", "/admin/providers/new", "/admin/providers/1", "/admin/providers/1/delete"} {
		for _, role := range []string{"", "User"} {
			a := &App{}
			mux := http.NewServeMux()
			a.registerUpstreamAdmin(mux)
			r := httptest.NewRequest("GET", path, nil)
			if role != "" {
				r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: db.User{Role: role}}))
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			want := 303
			if role != "" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s: %d", path, w.Code)
			}
		}
	}
}
func TestAdminUpstreamLifecycle(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/auth", issuer+"/token", issuer+"/user", issuer+"/keys")
	}))
	defer srv.Close()
	issuer = srv.URL
	mux := http.NewServeMux()
	a.registerUpstreamAdmin(mux)
	request := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/admin/providers/new", nil); w.Code != 200 || strings.Contains(w.Body.String(), `name="slug"`) {
		t.Fatalf("new provider should generate its slug: status %d", w.Code)
	}
	form := url.Values{"name": {"Example"}, "issuer": {issuer}, "client_id": {"client"}, "client_secret": {"never-render-this-secret"}, "scopes": {"openid email"}, "signing_alg": {"RS256"}, "pkce": {"on"}, "enabled": {"on"}}
	if w := request("POST", "/admin/providers", form); w.Code != 303 {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	p, err := a.Q.UpstreamProviderBySlug(ctx, "example")
	if err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/admin/providers", form); w.Code != 303 {
		t.Fatalf("duplicate-name create %d %s", w.Code, w.Body.String())
	}
	if _, err := a.Q.UpstreamProviderBySlug(ctx, "example-2"); err != nil {
		t.Fatal("duplicate provider name did not receive unique slug:", err)
	}
	// Deletion does not release login URLs for a different provider.
	duplicate, err := a.Q.UpstreamProviderBySlug(ctx, "example-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Q.DeleteUpstreamProvider(ctx, duplicate.ID); err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/admin/providers", form); w.Code != 303 {
		t.Fatalf("create after deleted slug: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.Q.UpstreamProviderBySlug(ctx, "example-3"); err != nil {
		t.Fatal(err)
	}
	// Parallel creates must each get a distinct slug.
	statuses := make(chan int, 3)
	for range 3 {
		go func() { statuses <- request("POST", "/admin/providers", form).Code }()
	}
	for range 3 {
		if code := <-statuses; code != 303 {
			t.Errorf("concurrent create: %d", code)
		}
	}
	for _, slug := range []string{"example-4", "example-5", "example-6"} {
		if _, err := a.Q.UpstreamProviderBySlug(ctx, slug); err != nil {
			t.Fatal(slug, err)
		}
	}
	path := fmt.Sprint("/admin/providers/", p.ID)
	if w := request("GET", path, nil); w.Code != 200 || strings.Contains(w.Body.String(), p.ClientSecret) || !strings.Contains(w.Body.String(), "/login/example/callback") {
		t.Fatalf("unsafe edit view status %d", w.Code)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: actor.ID, TokenHash: "upstream-admin-test", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Q.BindUpstreamSession(ctx, db.BindUpstreamSessionParams{SessionID: s.ID, ProviderID: p.ID, Subject: "subject", ProviderRevision: p.Revision, TokenIssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := a.Q.CreateLoginSession(ctx, db.CreateLoginSessionParams{TokenHash: "provider-pending", InternalToken: "provider-internal", Provider: p.Slug, State: []byte(`{}`), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // Editing unchanged issuer must work offline.
	form.Set("client_secret", "")
	form.Del("enabled")
	form.Set("name", "Renamed")
	if w := request("POST", path, form); w.Code != 303 {
		t.Fatalf("edit %d %s", w.Code, w.Body.String())
	}
	updated, err := a.Q.GetUpstreamProvider(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Slug != "example" || updated.Enabled || updated.ClientSecret != p.ClientSecret || updated.Revision != p.Revision+1 {
		t.Fatal("edit did not preserve secret or revise provider")
	}
	if _, err = a.Q.GetSession(ctx, s.ID); !notFound(err) {
		t.Fatalf("provider session survived: %v", err)
	}
	if _, err = a.Q.GetLoginSession(ctx, pending.ID); !notFound(err) {
		t.Fatalf("pending provider login survived: %v", err)
	}
	if w := request("POST", path+"/delete", nil); w.Code != 303 {
		t.Fatalf("delete %d", w.Code)
	}
	updated, err = a.Q.GetUpstreamProvider(ctx, p.ID)
	if err != nil || updated.DeletedAt == nil || updated.Enabled {
		t.Fatal("provider not soft deleted")
	}
}

func TestAdminUpstreamCSRF(t *testing.T) {
	a := &App{Config: Config{Domain: "https://auth.example.com"}, secret: "secret"}
	mux := http.NewServeMux()
	a.registerUpstreamAdmin(mux)
	for _, path := range []string{"/admin/providers", "/admin/providers/1", "/admin/providers/1/delete"} {
		r := httptest.NewRequest("POST", "https://auth.example.com"+path, nil)
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: db.User{Role: "Admin"}}))
		w := httptest.NewRecorder()
		a.middleware(mux).ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s missing CSRF: %d", path, w.Code)
		}
	}
}

func TestGeneratedUpstreamSlugs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		attempt int
		want    string
	}{
		{"Example Login", 1, "example-login"},
		{"  Example / Login!  ", 2, "example-login-2"},
		{"PASSWORD", 1, "provider-password"},
		{"MFA", 1, "provider-mfa"},
		{"日本語", 1, "provider"},
		{strings.Repeat("a", 100), 2, strings.Repeat("a", 61) + "-2"},
	} {
		if got := upstreamProviderSlug(tc.name, tc.attempt); got != tc.want {
			t.Errorf("%q attempt %d: got %q want %q", tc.name, tc.attempt, got, tc.want)
		}
	}
}
