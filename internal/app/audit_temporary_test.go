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
	"github.com/le0developer/guard/internal/security"
)

func TestAuditGroupDeletionOpensClient(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "outsider", Role: "User", WebauthnUserID: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "restricted"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "restricted", Slug: "restricted", ClientType: "Oidc", ClientID: "public-client", ClientSecret: "secret", SessionLifetimeS: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Q.AdminSaveRule(ctx, db.AdminSaveRuleParams{ClientID: c.ID, GroupID: g.ID, AccessControl: "Allow"}); err != nil {
		t.Fatal(err)
	}
	before, err := a.permitted(ctx, a.Q, c.ID, outsider.ID)
	if err != nil || before {
		t.Fatalf("before=%v err=%v", before, err)
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/admin/groups/%d/delete", g.ID), nil)
	r.SetPathValue("id", fmt.Sprint(g.ID))
	w := httptest.NewRecorder()
	if err = a.adminDelete(w, r, &identity{User: actor}, "groups"); err != nil {
		t.Fatal(err)
	}
	after, err := a.permitted(ctx, a.Q, c.ID, outsider.ID)
	if err != nil || !after {
		t.Fatalf("after=%v err=%v", after, err)
	}
	t.Log("confirmed: outsider denied before group deletion, allowed afterward")
}

func TestAuditRevokedAdminCanPromoteAccomplice(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "former-admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "accomplice", Role: "User", WebauthnUserID: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: actor.ID, TokenHash: security.Hash("audit-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	entered, resume := make(chan struct{}), make(chan struct{})
	h := a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-resume; mux.ServeHTTP(w, r) }))
	form := url.Values{"role": {"Admin"}, "current_role": {"User"}}
	r := httptest.NewRequest("POST", fmt.Sprintf("/admin/users/%d/role", target.ID), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "session", Value: "audit-session"})
	// Obtain the same CSRF token the middleware derives for this session/IP.
	probe := httptest.NewRecorder()
	a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { form.Set("csrf_token", csrf(r)) })).ServeHTTP(probe, httptest.NewRequest("GET", "/", nil))
	probeReq := httptest.NewRequest("GET", "/", nil)
	probeReq.AddCookie(&http.Cookie{Name: "session", Value: "audit-session"})
	a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { form.Set("csrf_token", csrf(r)) })).ServeHTTP(httptest.NewRecorder(), probeReq)
	r.Body = http.NoBody
	r = httptest.NewRequest("POST", r.URL.String(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "session", Value: "audit-session"})
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not authenticate")
	}
	p := adminUserParams(actor)
	p.Role = "User"
	if _, err = a.Q.UpdateUser(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = adminRevokeUser(ctx, a.Q, actor.ID); err != nil {
		t.Fatal(err)
	}
	close(resume)
	<-done
	current, err := a.Q.GetUser(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != 303 || current.Role != "Admin" {
		t.Fatalf("status=%d role=%s body=%s", w.Code, current.Role, w.Body.String())
	}
	t.Log("confirmed: request authenticated before demotion promoted accomplice after actor demotion and session revocation")
}
