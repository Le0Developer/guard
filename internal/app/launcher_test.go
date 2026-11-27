package app

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
)

func TestHomeAppLauncherAccessAndLinks(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	user, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "launcher-user", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	create := func(name, kind string, deleted bool) db.Client {
		t.Helper()
		p := db.CreateClientParams{Name: name, Slug: security.Token(), ClientID: security.Token(), ClientSecret: "must-not-leak", ClientType: kind, SessionLifetimeS: 3600}
		if deleted {
			p.DeletedAt = ptr(time.Now())
		}
		c, e := a.Q.CreateClient(ctx, p)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	public := create("Public Wiki", "Oidc", false)
	allowed := create("Staff Portal", "ForwardAuth", false)
	denied := create("Denied App", "Oidc", false)
	unmatched := create("Unmatched App", "Oidc", false)
	create("Deleted App", "Oidc", true)
	create("No Link App", "Oidc", false)
	group, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Staff"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: group.ID, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: other.ID, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}
	outsider, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Outsiders"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []db.CreateClientAccessRuleParams{
		{ClientID: allowed.ID, GroupID: group.ID, AccessControl: "Allow"},
		{ClientID: denied.ID, GroupID: group.ID, AccessControl: "Allow"},
		{ClientID: denied.ID, GroupID: other.ID, AccessControl: "Deny"},
		{ClientID: unmatched.ID, GroupID: outsider.ID, AccessControl: "Allow"},
	} {
		if _, err = a.Q.CreateClientAccessRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		c   db.Client
		uri string
	}{
		{public, "https://wiki.example.com:8443/oauth/callback?state=ignored"},
		{public, "https://second.example.com/callback"},
		{allowed, "https://portal.example.com"},
	} {
		if _, err := a.Q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: tc.c.ID, RedirectUri: tc.uri}); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: user}))
	w := httptest.NewRecorder()
	a.home(w, r)
	html := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("home: %d %s", w.Code, html)
	}
	for _, want := range []string{"App launcher", "Public Wiki", "Staff Portal", "No Link App", `href="https://wiki.example.com:8443"`, `href="https://portal.example.com"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, hidden := range []string{"Denied App", "Unmatched App", "Deleted App", "must-not-leak", "https://second.example.com", "/oauth/callback", "state=ignored"} {
		if strings.Contains(html, hidden) {
			t.Errorf("launcher leaked %s", hidden)
		}
	}
	if err := a.Q.DeleteGroupMember(ctx, db.DeleteGroupMemberParams{GroupID: group.ID, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.home(w, r)
	if strings.Contains(w.Body.String(), "Staff Portal") {
		t.Fatal("launcher ignored membership removal")
	}
}

func TestHomeAppLauncherEmpty(t *testing.T) {
	a := testApp(t)
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: db.User{Username: "alice", Role: "User"}}))
	w := httptest.NewRecorder()
	a.home(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "No apps available") {
		t.Fatalf("missing launcher empty state: %d %s", w.Code, w.Body.String())
	}
}
