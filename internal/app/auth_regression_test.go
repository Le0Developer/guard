package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

func TestAuthRegressionUpstreamStateProtectsVerifier(t *testing.T) {
	a := testApp(t)
	calls := 0
	var verifier string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.FormValue("code_verifier") != verifier {
			t.Error("token exchange did not send the private verifier")
		}
		http.Error(w, "rejected for test", http.StatusBadRequest)
	}))
	defer upstream.Close()
	p, err := a.Q.CreateUpstreamProvider(context.Background(), db.CreateUpstreamProviderParams{Slug: "example", Name: "Example", Issuer: upstream.URL, AuthorizeUrl: upstream.URL + "/authorize", TokenUrl: upstream.URL + "/token", UserinfoUrl: upstream.URL + "/userinfo", JwksUrl: upstream.URL + "/keys", ClientID: "client", ClientSecret: "secret", Scopes: "openid profile email", Pkce: true, SigningAlg: "RS256", Enabled: true, BackchannelLogoutEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/login/example", nil)
	r.SetPathValue("method", p.Slug)
	w := httptest.NewRecorder()
	a.login(w, r)
	if w.Code != 303 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "login_session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing login cookie")
	}
	l, err := a.Q.LoginSessionByTokenHash(context.Background(), security.Hash(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	verifier = l.InternalToken
	mac := hmac.New(sha256.New, []byte(l.InternalToken))
	mac.Write([]byte("guard-upstream-oidc-state\x00"))
	mac.Write([]byte(p.Slug))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	other := hmac.New(sha256.New, []byte(l.InternalToken))
	other.Write([]byte("guard-upstream-oidc-state\x00different-provider"))
	foreignState := base64.RawURLEncoding.EncodeToString(other.Sum(nil))
	state := u.Query().Get("state")
	if state != expected || state == l.InternalToken || oauthPKCE(state, u.Query().Get("code_challenge"), "S256") {
		t.Errorf("public state must be provider-bound HMAC and must not disclose PKCE verifier")
	}
	if !oauthPKCE(l.InternalToken, u.Query().Get("code_challenge"), "S256") {
		t.Error("stored verifier does not satisfy challenge")
	}
	for _, tc := range []struct {
		state         string
		status, calls int
	}{{l.InternalToken, 400, 0}, {foreignState, 400, 0}, {expected, 502, 1}} {
		r = httptest.NewRequest("GET", "/login/example/callback?"+url.Values{"state": {tc.state}, "code": {"code"}}.Encode(), nil)
		r.SetPathValue("method", p.Slug)
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		a.upstreamCallback(w, r)
		if w.Code != tc.status || calls != tc.calls {
			t.Errorf("callback: status=%d token calls=%d, want %d/%d", w.Code, calls, tc.status, tc.calls)
		}
	}
}

func TestAuthRegressionStaleManagementReturnsToPage(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	target, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "target", Role: "User", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(security.Token()), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Pool.Exec(ctx, "UPDATE sessions SET created_at=now()-interval '6 minutes' WHERE id=$1", s.ID); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"/security", "/account/security", fmt.Sprintf("/admin/users/%d/security", target.ID)} {
		t.Run(base, func(t *testing.T) {
			r := httptest.NewRequest("POST", base+"/totp", strings.NewReader("name=phone"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if strings.HasPrefix(base, "/admin/") {
				r.SetPathValue("id", fmt.Sprint(target.ID))
			}
			r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: u, Session: s}))
			w := httptest.NewRecorder()
			a.mfaManage(w, r)
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != 303 || location.Path != "/login" || location.Query().Get("r") != base {
				t.Fatalf("stale form redirects %d %q; want login returning to %s", w.Code, w.Header().Get("Location"), base)
			}
		})
	}
}
