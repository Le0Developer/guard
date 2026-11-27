package app

import (
	"context"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwardOriginalRejectsAmbiguousHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/auth_request", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Uri", "//evil.example/")
	if _, _, err := forwardOriginal(r); err == nil {
		t.Fatal("accepted scheme-relative URI")
	}
	r.Header.Set("X-Forwarded-Uri", "/private")
	r.Header.Add("X-Forwarded-Host", "evil.example")
	if _, _, err := forwardOriginal(r); err == nil {
		t.Fatal("accepted duplicate host")
	}
}
func TestForwardBrowserBindingAndReplay(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "forward", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash("guard"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "App", Slug: "app", ClientType: "ForwardAuth", ClientID: "forward-client", ClientSecret: "secret", SessionLifetimeS: 600})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: c.ID, RedirectUri: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	state, browser, authorize, err := a.forwardStart(ctx, c, "https://app.example.com/private")
	if err != nil {
		t.Fatal(err)
	}
	if authorize == "" {
		t.Fatal("no auth URL")
	}
	rawCode := security.Token()
	codeHash := security.Hash(rawCode)
	f, err := a.Q.ForwardAuthRequestByStateHash(ctx, security.Hash(state))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.UpdateForwardAuthRequest(ctx, db.UpdateForwardAuthRequestParams{ID: f.ID, StateHash: f.StateHash, BrowserHash: f.BrowserHash, CodeHash: &codeHash, ClientID: c.ID, Origin: f.Origin, ReturnUri: f.ReturnUri, UserID: &u.ID, SessionID: &s.ID, ExpiresAt: f.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = a.forwardFinish(ctx, "https://app.example.com", state, rawCode, "wrong"); err == nil {
		t.Fatal("accepted unbound browser")
	}
	token, redirect, _, err := a.forwardFinish(ctx, "https://app.example.com", state, rawCode, browser)
	if err != nil || token == "" || redirect != "https://app.example.com/private" {
		t.Fatalf("finish %q %q %v", token, redirect, err)
	}
	if _, _, _, err = a.forwardFinish(ctx, "https://app.example.com", state, rawCode, browser); err == nil {
		t.Fatal("accepted replay")
	}
}
