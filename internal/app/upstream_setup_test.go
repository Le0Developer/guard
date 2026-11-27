package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/le0developer/guard/internal/db"
)

func TestManualOAuth2ProviderLogin(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "alice", Email: "alice@example.com", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var verified atomic.Bool
	verified.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			id, secret, ok := r.BasicAuth()
			if !ok || id != "client" || secret != "secret" || r.FormValue("client_secret") != "" || r.FormValue("client_id") != "" {
				t.Error("missing basic client authentication")
			}
			if r.FormValue("code_verifier") == "" {
				t.Error("missing PKCE verifier")
			}
			fmt.Fprint(w, `{"access_token":"opaque-access-token","token_type":"Bearer"}`)
		case "/profile":
			if r.Header.Get("Authorization") != "Bearer opaque-access-token" {
				t.Error("missing bearer token")
			}
			fmt.Fprintf(w, `{"account":{"id":9007199254740993},"emails":[{"address":"alice@example.com","verified":%t}]}`, verified.Load())
		default:
			t.Errorf("unexpected discovery or JWKS request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	mux := http.NewServeMux()
	a.registerUpstreamAdmin(mux)
	form := url.Values{"name": {"Generic"}, "configuration_mode": {"oauth2"}, "authorize_url": {server.URL + "/authorize"}, "token_url": {server.URL + "/token"}, "userinfo_url": {server.URL + "/profile"}, "client_id": {"client"}, "client_secret": {"secret"}, "client_auth_method": {"client_secret_post"}, "scopes": {"profile email"}, "subject_field": {"account.id"}, "email_field": {"emails.0.address"}, "email_verified_field": {"emails.0.verified"}, "pkce": {"on"}, "enabled": {"on"}, "backchannel_logout_enabled": {"on"}}
	r := httptest.NewRequest("POST", "/admin/providers", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("manual OAuth2 create: %d %s", w.Code, w.Body.String())
	}
	p, err := a.Q.UpstreamProviderBySlug(ctx, "generic")
	if err != nil {
		t.Fatal(err)
	}
	if p.BackchannelLogoutEnabled {
		t.Fatal("plain OAuth2 must not accept OIDC logout tokens")
	}
	for _, isVerified := range []bool{false, true} {
		verified.Store(isVerified)
		r = httptest.NewRequest("GET", "/login/generic", nil)
		r.SetPathValue("method", "generic")
		w = httptest.NewRecorder()
		a.login(w, r)
		if w.Code != 303 {
			t.Fatalf("login start: %d %s", w.Code, w.Body.String())
		}
		target, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if target.Query().Get("nonce") != "" {
			t.Fatal("OAuth2 authorization must not send OIDC nonce")
		}
		callback := httptest.NewRequest("GET", "/login/generic/callback?"+url.Values{"state": {target.Query().Get("state")}, "code": {"code"}}.Encode(), nil)
		callback.SetPathValue("method", "generic")
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == "login_session" {
				callback.AddCookie(cookie)
			}
		}
		w = httptest.NewRecorder()
		a.upstreamCallback(w, callback)
		if !isVerified {
			if w.Code != 403 {
				t.Fatalf("unverified email accepted: %d %s", w.Code, w.Body.String())
			}
			continue
		}
		if w.Code != 303 {
			t.Fatalf("OAuth2 callback: %d %s", w.Code, w.Body.String())
		}
		sessions, err := a.Q.SessionsByUserId(ctx, actor.ID)
		if err != nil || len(sessions) != 1 {
			t.Fatalf("sessions: %v %v", sessions, err)
		}
		binding, err := a.Q.GetUpstreamSession(ctx, sessions[0].ID)
		if err != nil || binding.Subject != "9007199254740993" {
			t.Fatalf("subject binding lost precision: %+v %v", binding, err)
		}
	}
}

func TestAdminProviderExplicitConfigurationURL(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/oidc-config.json" {
			t.Errorf("unexpected metadata path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": base + "/tenant/", "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "userinfo_endpoint": base + "/userinfo", "jwks_uri": base + "/jwks", "id_token_signing_alg_values_supported": []string{"none", "RS384", "HS256"}})
	}))
	defer server.Close()
	base = server.URL
	form := url.Values{"name": {"Discovery"}, "configuration_mode": {"oidc_discovery"}, "discovery_url": {base + "/custom/oidc-config.json"}, "client_id": {"client"}, "client_secret": {"secret"}, "scopes": {"openid email"}, "signing_alg": {"HS256"}, "enabled": {"on"}}
	r := httptest.NewRequest("POST", "/admin/providers", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
	mux := http.NewServeMux()
	a.registerUpstreamAdmin(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("configuration URL: %d %s", w.Code, w.Body.String())
	}
	p, err := a.Q.UpstreamProviderBySlug(ctx, "discovery")
	if err != nil || p.Issuer != base+"/tenant/" || p.SigningAlg != "RS384" {
		t.Fatalf("metadata issuer: %+v %v", p, err)
	}
}

func TestManualOIDCSetupPreservesValidation(t *testing.T) {
	f := newUpstreamFixture(t)
	// The fixture has no discovery endpoint: manual setup must not request one.
	form := url.Values{"name": {"Work"}, "configuration_mode": {"oidc_manual"}, "issuer": {f.p.Issuer}, "authorize_url": {f.p.AuthorizeUrl}, "token_url": {f.p.TokenUrl}, "userinfo_url": {f.p.UserinfoUrl}, "jwks_url": {f.p.JwksUrl}, "client_id": {f.p.ClientID}, "scopes": {"openid email"}, "signing_alg": {"RS256"}, "pkce": {"on"}, "enabled": {"on"}, "backchannel_logout_enabled": {"on"}}
	r := httptest.NewRequest("POST", fmt.Sprintf("/admin/providers/%d", f.p.ID), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: f.user}))
	admin := f.user
	admin.Role = "Admin"
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: admin}))
	mux := http.NewServeMux()
	f.a.registerUpstreamAdmin(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("manual OIDC edit: %d %s", w.Code, w.Body.String())
	}
	updated, err := f.a.Q.GetUpstreamProvider(context.Background(), f.p.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.p = updated
	_, _ = f.login(t)
	f.userinfoSubject.Store("wrong-subject")
	cookie, query := f.begin(t)
	w = f.callback(t, cookie, query)
	if w.Code != 403 {
		t.Fatalf("manual OIDC accepted mismatched subject: %d %s", w.Code, w.Body.String())
	}
}

func TestOAuth2ProfileMappingRejectsUnsafeIdentity(t *testing.T) {
	p := db.UpstreamProvider{SubjectField: "account.id", EmailField: "emails.0.address", EmailVerifiedField: "emails.0.verified"}
	for _, raw := range []string{
		`{"account":{"id":1},"emails":[{"address":"alice@example.com","verified":false}]}`,
		`{"account":{"id":1},"emails":[{"address":"alice@example.com","verified":"true"}]}`,
		`{"account":{"id":true},"emails":[{"address":"alice@example.com","verified":true}]}`,
		`{"account":{"id":null},"emails":[{"address":"alice@example.com","verified":true}]}`,
		`{"account":{"id":1},"emails":[]}`,
		`{"account":{"id":1,"id":2},"emails":[{"address":"alice@example.com","verified":true}]}`,
	} {
		if profile, err := parseOAuth2Profile([]byte(raw), p); err == nil {
			t.Errorf("accepted unsafe profile %s: %+v", raw, profile)
		}
	}
}
