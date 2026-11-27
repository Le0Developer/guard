package app

import (
	"context"
	"github.com/le0developer/guard/internal/db"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func introspectionFixture(t *testing.T) oauthFixture {
	f := newOAuthFixture(t)
	mux := http.NewServeMux()
	f.a.registerOAuth(mux)
	f.a.registerIntrospection(mux)
	f.h = mux
	return f
}
func assertIntrospectionInactive(t *testing.T, f oauthFixture, token string) {
	t.Helper()
	status, out := f.post("/oauth2/introspect", url.Values{"token": {token}})
	if status != 200 || len(out) != 1 || out["active"] != false {
		t.Fatalf("inactive: %d %v", status, out)
	}
}
func TestIntrospectionActiveAndRotation(t *testing.T) {
	f := introspectionFixture(t)
	status, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("mint: %d %v", status, tokens)
	}
	access, refresh := tokens["access_token"].(string), tokens["refresh_token"].(string)
	for _, test := range []struct {
		token, hint string
		bearer      bool
	}{{access, "refresh_token", true}, {refresh, "access_token", false}} {
		status, out := f.post("/oauth2/introspect", url.Values{"token": {test.token}, "token_type_hint": {test.hint}})
		if status != 200 || out["active"] != true || out["client_id"] != "client" || out["username"] != "oauth-alice" || out["scope"] != "openid profile email" || out["exp"] == nil || out["iat"] == nil || out["iss"] != f.a.oauthIssuer(f.client) {
			t.Fatalf("active: %d %v", status, out)
		}
		if _, ok := out["token_type"]; ok != test.bearer {
			t.Fatalf("type: %v", out)
		}
	}
	status, next := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != 200 {
		t.Fatalf("rotation: %d %v", status, next)
	}
	assertIntrospectionInactive(t, f, refresh)
	f.post("/oauth2/revoke", url.Values{"token": {next["refresh_token"].(string)}})
	assertIntrospectionInactive(t, f, next["access_token"].(string))
}
func TestIntrospectionClientScoped(t *testing.T) {
	f := introspectionFixture(t)
	_, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	assertIntrospectionInactive(t, f, "unknown")
	_, err := f.a.Q.CreateClient(context.Background(), db.CreateClientParams{Name: "Other", Slug: "other", ClientType: "Oidc", ClientID: "other", ClientSecret: "secret", SessionLifetimeS: 1800})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/oauth2/introspect", strings.NewReader(url.Values{"token": {tokens["access_token"].(string)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("other", "secret")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` {
		t.Fatalf("cross-client: %d %s", w.Code, w.Body)
	}
}
func TestIntrospectionInputAndAuthentication(t *testing.T) {
	f := introspectionFixture(t)
	for _, test := range []struct {
		name, body, mime, auth string
		status                 int
	}{
		{"missing", "", "application/x-www-form-urlencoded", "basic", 400},
		{"oversize", "token=" + strings.Repeat("x", 513), "application/x-www-form-urlencoded", "basic", 400},
		{"duplicate", "token=a&token=b", "application/x-www-form-urlencoded", "basic", 400},
		{"wrong mime", "token=a", "text/plain", "basic", 400},
		{"no auth", "token=a", "application/x-www-form-urlencoded", "", 401},
		{"bad secret", "token=a", "application/x-www-form-urlencoded", "bad", 401},
		{"mixed auth", "token=a&client_id=client&client_secret=secret", "application/x-www-form-urlencoded", "basic", 401},
		{"post auth", "token=a&client_id=client&client_secret=secret", "application/x-www-form-urlencoded", "", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/oauth2/introspect", strings.NewReader(test.body))
			r.Header.Set("Content-Type", test.mime)
			if test.auth != "" {
				secret := "secret"
				if test.auth == "bad" {
					secret = "wrong"
				}
				r.SetBasicAuth("client", secret)
			}
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("headers %v", w.Header())
			}
		})
	}
}

func TestIntrospectionLiveAuthorization(t *testing.T) {
	for _, mode := range []string{"session", "account", "access", "expired access", "expired refresh"} {
		t.Run(mode, func(t *testing.T) {
			f := introspectionFixture(t)
			_, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
			ctx := context.Background()
			var err error
			switch mode {
			case "session":
				err = f.a.Q.DeleteSession(ctx, f.who.Session.ID)
			case "account":
				u := f.who.User
				_, err = f.a.Q.UpdateUser(ctx, db.UpdateUserParams{ID: u.ID, Username: u.Username, Email: u.Email, Password: u.Password, Role: u.Role, Disabled: true, WebauthnUserID: u.WebauthnUserID})
			case "access":
				g, e := f.a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "restricted"})
				if e != nil {
					t.Fatal(e)
				}
				_, err = f.a.Q.CreateClientAccessRule(ctx, db.CreateClientAccessRuleParams{ClientID: f.client.ID, GroupID: g.ID, AccessControl: "Allow"})
			case "expired access":
				_, err = f.a.Pool.Exec(ctx, `UPDATE oauth_tokens SET access_expires_at = now() - interval '1 second'`)
			case "expired refresh":
				_, err = f.a.Pool.Exec(ctx, `UPDATE oauth_tokens SET expires_at = now() - interval '1 second'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertIntrospectionInactive(t, f, tokens["access_token"].(string))
			if mode != "expired access" {
				assertIntrospectionInactive(t, f, tokens["refresh_token"].(string))
			} else {
				status, out := f.post("/oauth2/introspect", url.Values{"token": {tokens["refresh_token"].(string)}})
				if status != 200 || out["active"] != true {
					t.Fatalf("refresh lifetime: %d %v", status, out)
				}
			}
		})
	}
}
func TestIntrospectionDatabaseFailure(t *testing.T) {
	f := introspectionFixture(t)
	f.a.Pool.Close()
	status, out := f.post("/oauth2/introspect", url.Values{"token": {"unknown"}})
	if status != 503 || out["error"] != "server_error" || out["active"] != nil {
		t.Fatalf("failure must close: %d %v", status, out)
	}
}
func TestIntrospectionJournalFailure(t *testing.T) {
	f := introspectionFixture(t)
	_, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	_, err := f.a.Pool.Exec(context.Background(), `UPDATE clients SET detailed_logging = true; ALTER TABLE access_logs ADD CONSTRAINT introspection_reject CHECK (false) NOT VALID`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.a.Pool.Exec(context.Background(), `ALTER TABLE access_logs DROP CONSTRAINT introspection_reject`)
	status, out := f.post("/oauth2/introspect", url.Values{"token": {tokens["access_token"].(string)}})
	if status != 503 || out["active"] == true {
		t.Fatalf("journal failure: %d %v", status, out)
	}
}
