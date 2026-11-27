package app

import (
	"context"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminAuthorization(t *testing.T) {
	for _, path := range []string{"/admin", "/admin/users", "/admin/groups/new", "/admin/clients/1", "/admin/access-log"} {
		for _, role := range []string{"", "User"} {
			a := &App{}
			mux := http.NewServeMux()
			a.registerAdmin(mux)
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
				t.Fatalf("%s role %q: got %d want %d", path, role, w.Code, want)
			}
		}
	}
}
func TestAdminRedirectValidation(t *testing.T) {
	for _, s := range []string{"https://example.com/#", "https://*.example.com/callback", "https:///callback", "https://u:p@example.com", "https://example.com/a b", "https://example.com/\\x", "javascript:alert(1)"} {
		if adminRedirectError(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"https://example.com/callback?x=%2F", "http://localhost:8080/callback"} {
		if err := adminRedirectError(s); err != nil {
			t.Errorf("rejected %q: %v", s, err)
		}
	}
}

func TestAdminPersistedLifecycle(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if e != nil {
		t.Fatal(e)
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
	post := func(path string, form url.Values) {
		t.Helper()
		w := request("POST", path, form)
		if w.Code != 303 {
			t.Fatalf("POST %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	post("/admin/users", url.Values{"username": {"alice"}, "role": {"User"}})
	u, e := a.Q.UserByUsername(ctx, "alice")
	if e != nil {
		t.Fatal(e)
	}
	userPath := fmt.Sprintf("/admin/users/%d", u.ID)
	s, e := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: "test-session", ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/admin", "/admin/users", "/admin/users/new", userPath, userPath + "/password", userPath + "/role", userPath + "/delete", "/admin/groups", "/admin/groups/new", "/admin/clients", "/admin/clients/new", "/admin/audit", "/admin/access-log"} {
		w := request("GET", path, nil)
		if w.Code != 200 {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := request("POST", userPath, url.Values{"username": {"alice"}, "role": {"Admin"}}); w.Code != 422 {
		t.Fatalf("role bypass %d", w.Code)
	}
	post(userPath+"/role", url.Values{"role": {"Admin"}, "current_role": {"User"}})
	if _, e = a.Q.GetSession(ctx, s.ID); !notFound(e) {
		t.Fatalf("session survived role change: %v", e)
	}
	if w := request("POST", userPath+"/role", url.Values{"role": {"User"}, "current_role": {"User"}}); w.Code != 422 {
		t.Fatalf("stale confirmation %d", w.Code)
	}
	post(userPath+"/password", url.Values{"password": {"a new password"}, "confirm_password": {"a new password"}})
	u, e = a.Q.GetUser(ctx, u.ID)
	if e != nil || !security.VerifyPassword("a new password", u.Password) || u.MfaRevision != 2 {
		t.Fatalf("password/revision not updated %+v %v", u, e)
	}
	post("/admin/groups", url.Values{"name": {"Staff"}})
	groups, e := a.Q.ListGroups(ctx)
	if e != nil || len(groups) != 1 {
		t.Fatal(groups, e)
	}
	g := groups[0]
	groupPath := fmt.Sprintf("/admin/groups/%d", g.ID)
	post(groupPath+"/members", url.Values{"user_id": {fmt.Sprint(u.ID)}})
	post(groupPath+"/members", url.Values{"user_id": {fmt.Sprint(u.ID)}})
	members, e := a.Q.ListGroupMembers(ctx)
	if e != nil || len(members) != 1 {
		t.Fatal(members, e)
	}
	post("/admin/clients", url.Values{"name": {"App"}, "client_type": {"Oidc"}, "session_lifetime_s": {"3600"}, "require_pkce": {"on"}})
	clients, e := a.Q.ListClients(ctx)
	if e != nil || len(clients) != 1 {
		t.Fatal(clients, e)
	}
	c := clients[0]
	clientPath := fmt.Sprintf("/admin/clients/%d", c.ID)
	post(clientPath+"/redirects", url.Values{"redirect_uri": {"https://app.example/callback?x=%2F"}})
	redirects, e := a.Q.ClientRedirectsByClientId(ctx, c.ID)
	if e != nil || len(redirects) != 1 || redirects[0].RedirectUri != "https://app.example/callback?x=%2F" {
		t.Fatal(redirects, e)
	}
	post(clientPath+"/rules", url.Values{"group_id": {fmt.Sprint(g.ID)}, "priority": {"-10"}, "access_control": {"allow"}})
	allowed, e := a.permitted(ctx, a.Q, c.ID, u.ID)
	if e != nil || !allowed {
		t.Fatal("allow rule", allowed, e)
	}
	post(clientPath+"/rules", url.Values{"group_id": {fmt.Sprint(g.ID)}, "priority": {"-10"}, "access_control": {"deny"}})
	allowed, e = a.permitted(ctx, a.Q, c.ID, u.ID)
	if e != nil || allowed {
		t.Fatal("deny rule", allowed, e)
	}
	if w := request("POST", clientPath+"/rotate-secret", nil); w.Code != 422 {
		t.Fatalf("unconfirmed rotation %d", w.Code)
	}
	post("/admin/clients", url.Values{"name": {"Other"}, "client_type": {"Oidc"}, "session_lifetime_s": {"3600"}})
	others, e := a.Q.ListClients(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var other db.Client
	for _, item := range others {
		if item.ID != c.ID {
			other = item
		}
	}
	cross := fmt.Sprintf("/admin/clients/%d/redirects/%d/remove", other.ID, redirects[0].ID)
	if w := request("POST", cross, nil); w.Code != 404 {
		t.Fatalf("cross-client redirect removal: %d", w.Code)
	}
	if w := request("POST", fmt.Sprintf("/admin/users/%d/delete", actor.ID), nil); w.Code != 422 {
		t.Fatalf("self-delete: %d", w.Code)
	}
	if w := request("POST", fmt.Sprintf("/admin/users/%d", actor.ID), url.Values{"username": {"admin"}, "disabled": {"on"}}); w.Code != 422 {
		t.Fatalf("self-disable: %d", w.Code)
	}
	post(clientPath+"/rotate-secret", url.Values{"confirm": {"rotate"}})
	rotated, e := a.Q.GetClient(ctx, c.ID)
	if e != nil || rotated.ClientSecret == c.ClientSecret {
		t.Fatal("secret unchanged", e)
	}
	for _, path := range []string{groupPath, groupPath + "/delete", clientPath, clientPath + "/delete", "/admin/audit"} {
		w := request("GET", path, nil)
		if w.Code != 200 {
			t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	post(userPath+"/delete", nil)
	u, e = a.Q.GetUser(ctx, u.ID)
	if e != nil || u.DeletedAt == nil || !u.Disabled {
		t.Fatal("user not deleted", e)
	}
	members, e = a.Q.ListGroupMembers(ctx)
	if e != nil || len(members) != 0 {
		t.Fatal("members retained", e)
	}
	post(clientPath+"/delete", nil)
	post(groupPath+"/delete", nil)
	for _, path := range []string{userPath, groupPath, clientPath} {
		if w := request("GET", path, nil); w.Code != 404 {
			t.Fatalf("deleted %s: %d", path, w.Code)
		}
	}
	logs, e := a.Q.ListAuditLogs(ctx)
	if e != nil || len(logs) < 10 {
		t.Fatal("audit missing", e)
	}
}
