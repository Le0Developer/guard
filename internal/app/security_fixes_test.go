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
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
)

func TestGroupDeletionKeepsClientsRestricted(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	group, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "restricted"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Oidc", "ForwardAuth"} {
		for _, keepRule := range []bool{false, true} {
			name := fmt.Sprintf("%s-%t", kind, keepRule)
			c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: name, Slug: name, ClientID: name, ClientSecret: "secret", ClientType: kind, SessionLifetimeS: 3600})
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Q.AdminSaveRule(ctx, db.AdminSaveRuleParams{ClientID: c.ID, GroupID: group.ID, AccessControl: "Allow"}); err != nil {
				t.Fatal(err)
			}
			if keepRule {
				if err = a.Q.AdminSaveRule(ctx, db.AdminSaveRuleParams{ClientID: c.ID, GroupID: other.ID, AccessControl: "Allow"}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/admin/groups/%d/delete", group.ID), nil)
	r.SetPathValue("id", fmt.Sprint(group.ID))
	if err = a.adminDelete(httptest.NewRecorder(), r, &identity{User: actor}, "groups"); err != nil {
		t.Fatal(err)
	}
	clients, err := a.Q.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		wantDisabled := strings.HasSuffix(c.Name, "-false")
		if c.Disabled != wantDisabled {
			t.Errorf("client %s disabled=%v, want %v", c.Name, c.Disabled, wantDisabled)
		}
		allowed, err := a.permitted(ctx, a.Q, c.ID, actor.ID)
		if err != nil || allowed {
			t.Errorf("client %s permits outsider after group deletion: %v, %v", c.Name, allowed, err)
		}
	}
}

func TestBootstrapAccountCanBeManaged(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "replacement", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	request := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/admin/users/0", nil); w.Code != 200 {
		t.Fatalf("bootstrap details: %d", w.Code)
	}
	session, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: 0, TokenHash: security.Hash("bootstrap-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if w := request("POST", "/admin/users/0/password", url.Values{"password": {"replacement-password"}, "confirm_password": {"replacement-password"}}); w.Code != 303 {
		t.Fatalf("rotate bootstrap password: %d %s", w.Code, w.Body.String())
	}
	u, err := a.Q.GetUser(ctx, 0)
	if err != nil || !security.VerifyPassword("replacement-password", u.Password) {
		t.Fatalf("password not rotated: %v", err)
	}
	if _, err = a.Q.GetSession(ctx, session.ID); !notFound(err) {
		t.Fatalf("old session survived: %v", err)
	}
	if w := request("POST", "/admin/users/0/role", url.Values{"role": {"User"}, "current_role": {"Admin"}}); w.Code != 303 {
		t.Fatalf("change bootstrap role: %d %s", w.Code, w.Body.String())
	}
	actorSession, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: actor.ID, TokenHash: security.Hash("replacement-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/admin/users/0/security", nil)
	r.SetPathValue("id", "0")
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor, Session: actorSession}))
	if err := transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, err := a.mfaContext(r, q)
		if err == nil && c.Target.ID != 0 {
			t.Fatal("wrong MFA target")
		}
		return err
	}); err != nil {
		t.Fatalf("bootstrap MFA management: %v", err)
	}
	if w := request("POST", "/admin/users/0", url.Values{"username": {"system"}, "disabled": {"on"}}); w.Code != 303 {
		t.Fatalf("disable bootstrap: %d %s", w.Code, w.Body.String())
	}
	u, err = a.Q.GetUser(ctx, 0)
	if err != nil || !u.Disabled {
		t.Fatalf("bootstrap not disabled: %v", err)
	}
	users, err := a.Q.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("editing bootstrap created another user: %v", err)
	}
	if err = a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	u, err = a.Q.GetUser(ctx, 0)
	if err != nil || !u.Disabled {
		t.Fatalf("restart reactivated bootstrap: %v", err)
	}
	if w := request("POST", "/admin/users/0/delete", nil); w.Code != 303 {
		t.Fatalf("delete bootstrap: %d %s", w.Code, w.Body.String())
	}
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	u, err = a.Q.GetUser(ctx, 0)
	if err != nil || u.DeletedAt == nil {
		t.Fatalf("deleted bootstrap recreated: %v", err)
	}
}

func TestAdminUserIDZeroIsValidOnlyForUsers(t *testing.T) {
	if id, err := adminID[ids.UserID]("0"); err != nil || id != 0 {
		t.Fatalf("bootstrap user ID rejected: %v", err)
	}
	for _, value := range []string{"", "-1", "invalid"} {
		if _, err := adminID[ids.UserID](value); err == nil {
			t.Errorf("invalid user ID accepted: %q", value)
		}
	}
	if _, err := adminID[ids.ClientID]("0"); err == nil {
		t.Fatal("zero client ID accepted")
	}
	if _, err := adminID[ids.GroupID]("0"); err == nil {
		t.Fatal("zero group ID accepted")
	}
}

func TestDisabledClientRejectsExistingTokens(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t)
	status, tokens := f.post("/oauth2/token", oauthCodeFields(code))
	if status != 200 {
		t.Fatalf("issue tokens: %d %v", status, tokens)
	}
	pending := f.code(t)
	if _, err := f.a.Q.SetClientDisabled(context.Background(), db.SetClientDisabledParams{ID: f.client.ID, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if status := f.info(tokens["access_token"].(string)); status != 401 {
		t.Fatalf("disabled client userinfo: %d", status)
	}
	for _, fields := range []url.Values{
		oauthCodeFields(pending),
		{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}},
	} {
		status, out := f.post("/oauth2/token", fields)
		if status != 401 || out["error"] != "invalid_client" {
			t.Fatalf("disabled client token grant: %d %v", status, out)
		}
	}
	apps, err := f.a.launcherApps(httptest.NewRequest("GET", "/", nil), f.who.User.ID)
	if err != nil || len(apps) != 0 {
		t.Fatalf("disabled client remains in launcher: %v %v", apps, err)
	}
	mux := http.NewServeMux()
	f.a.registerIntrospection(mux)
	r := httptest.NewRequest("POST", "/oauth2/introspect", strings.NewReader(url.Values{"token": {tokens["access_token"].(string)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("client", "secret")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("disabled client introspection: %d", w.Code)
	}
	// Re-enabling is explicit and restores access without changing the client ID.
	if _, err := f.a.Q.SetClientDisabled(context.Background(), db.SetClientDisabledParams{ID: f.client.ID, Disabled: false}); err != nil {
		t.Fatal(err)
	}
	if status := f.info(tokens["access_token"].(string)); status != 200 {
		t.Fatalf("enabled client userinfo: %d", status)
	}
}
