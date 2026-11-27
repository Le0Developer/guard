package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUpstreamReauthenticationRequiresFreshAuthTime(t *testing.T) {
	for _, mode := range []string{"missing", "stale", "fresh"} {
		t.Run(mode, func(t *testing.T) {
			f := newUpstreamFixture(t)
			if mode == "stale" {
				f.authTime.Store(time.Now().Add(-time.Hour).Unix())
			}
			if mode == "fresh" {
				f.authTime.Store(time.Now().Unix())
			}
			cookie, q := f.beginWithQuery(t, url.Values{"prompt": {"login"}})
			if q.Get("prompt") != "login" || q.Get("max_age") != "0" {
				t.Fatalf("freshness not sent upstream: %v", q)
			}
			w := f.callback(t, cookie, q)
			want := 403
			if mode == "fresh" {
				want = 303
			}
			if w.Code != want {
				t.Fatalf("callback %d, want %d: %s", w.Code, want, w.Body.String())
			}
		})
	}
}

func TestUpstreamAuthenticationTimeSurvivesSessionCreation(t *testing.T) {
	f := newUpstreamFixture(t)
	want := time.Now().Add(-time.Hour).Unix()
	f.authTime.Store(want)
	session, _ := f.login(t)
	if session.AuthTime != want {
		t.Fatalf("authentication time %d, want %d", session.AuthTime, want)
	}
}

func TestOAuthFreshnessSurvivesProviderChoice(t *testing.T) {
	f := newOAuthFixture(t)
	fields := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "code_challenge": {strings.Repeat("v", 43)}, "prompt": {"login"}, "max_age": {"0"}}
	r := httptest.NewRequest("GET", "/oauth2/authorize?"+fields.Encode(), nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	login, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if login.Query().Get("prompt") != "login" || login.Query().Get("max_age") != "0" {
		t.Fatalf("lost login freshness: %s", login)
	}
	// Force provider choice by configuring an upstream as well as password login.
	_, err = f.a.Pool.Exec(context.Background(), `INSERT INTO upstream_providers (slug,name,issuer,authorize_url,token_url,userinfo_url,jwks_url,client_id,client_secret,scopes,signing_alg,enabled) VALUES ('work','Work','https://upstream.example','https://upstream.example/authorize','https://upstream.example/token','https://upstream.example/userinfo','https://upstream.example/keys','guard','secret','openid email','RS256',true)`)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	f.a.login(w, httptest.NewRequest("GET", login.String(), nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "prompt=login") || !strings.Contains(w.Body.String(), "max_age=0") {
		t.Fatalf("provider choice loses freshness: %d %s", w.Code, w.Body.String())
	}
}

func TestUpstreamMaxAgeRejectsStaleAuthentication(t *testing.T) {
	for _, age := range []string{"0", "300"} {
		t.Run(age, func(t *testing.T) {
			f := newUpstreamFixture(t)
			f.authTime.Store(time.Now().Add(-time.Hour).Unix())
			cookie, q := f.beginWithQuery(t, url.Values{"max_age": {age}})
			if q.Get("max_age") != age {
				t.Fatalf("max_age not sent upstream: %v", q)
			}
			if w := f.callback(t, cookie, q); w.Code != 403 {
				t.Fatalf("stale authentication accepted: %d", w.Code)
			}
		})
	}
}

func TestOAuthAuthenticationTimeControlsFreshnessAndTokens(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(map[bool]string{true: "known", false: "unknown"}[known], func(t *testing.T) {
			f := newOAuthFixture(t)
			authTime := int64(0)
			if known {
				authTime = time.Now().Add(-time.Hour).Unix()
			}
			if err := f.a.Q.SetSessionAuthTime(context.Background(), db.SetSessionAuthTimeParams{ID: f.who.Session.ID, AuthTime: authTime}); err != nil {
				t.Fatal(err)
			}
			f.who.Session.AuthTime = authTime
			status, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
			if status != 200 {
				t.Fatalf("mint %d %v", status, tokens)
			}
			assertAuthTime := func(tokens map[string]any) {
				t.Helper()
				parts := strings.Split(tokens["id_token"].(string), ".")
				payload, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatal(err)
				}
				var claims map[string]any
				if err = json.Unmarshal(payload, &claims); err != nil {
					t.Fatal(err)
				}
				if known {
					if claims["auth_time"] != float64(authTime) {
						t.Fatalf("wrong auth_time: %v", claims)
					}
				} else if _, exists := claims["auth_time"]; exists {
					t.Fatalf("unknown authentication presented as fresh: %v", claims)
				}
			}
			assertAuthTime(tokens)
			status, refreshed := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
			if status != 200 {
				t.Fatalf("refresh %d %v", status, refreshed)
			}
			assertAuthTime(refreshed)
			fields := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "code_challenge": {strings.Repeat("v", 43)}, "prompt": {"none"}, "max_age": {"60"}}
			r := httptest.NewRequest("GET", "/oauth2/authorize?"+fields.Encode(), nil)
			r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, r)
			location, _ := url.Parse(w.Header().Get("Location"))
			if location.Query().Get("error") != "login_required" {
				t.Fatalf("session creation mistaken for authentication: %s", location)
			}
			err := transaction(context.Background(), f.a.Pool, func(q *db.Queries) error { _, err := f.a.mfaContext(r, q); return err })
			if !errors.Is(err, errMFARecent) {
				t.Fatalf("MFA management accepted stale authentication: %v", err)
			}
		})
	}
}

func TestOAuthOnlyProviderRejectsForcedReauthentication(t *testing.T) {
	f := newUpstreamFixture(t)
	if _, err := f.a.Pool.Exec(context.Background(), "UPDATE upstream_providers SET configuration_mode='oauth2' WHERE id=$1", f.p.ID); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/login/work?prompt=login", nil)
	r.SetPathValue("method", "work")
	w := httptest.NewRecorder()
	f.a.login(w, r)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("unverifiable reauthentication allowed: %d", w.Code)
	}
}

func TestUpstreamAuthenticationTimeSurvivesMFA(t *testing.T) {
	f := newUpstreamFixture(t)
	ctx := context.Background()
	authTime := time.Now().Add(-2 * time.Second).Unix()
	f.authTime.Store(authTime)
	sealed, err := f.a.mfaSeal(f.user.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.CreateTotpAuthenticator(ctx, db.CreateTotpAuthenticatorParams{UserID: f.user.ID, Name: "Phone", Secret: sealed, LastStep: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{UserID: f.user.ID, Hash: mfaRecoveryHash(f.user.ID, "backup-code")}); err != nil {
		t.Fatal(err)
	}
	cookie, query := f.beginWithQuery(t, url.Values{"prompt": {"login"}})
	w := f.callback(t, cookie, query)
	if w.Code != 303 || w.Header().Get("Location") != "/login/mfa" {
		t.Fatalf("MFA challenge %d %s", w.Code, w.Body.String())
	}
	var pending string
	for _, c := range w.Result().Cookies() {
		if c.Name == "mfa_pending" {
			pending = c.Value
		}
	}
	w = httptest.NewRecorder()
	f.a.mfaCode(w, mfaTestRequest(cookie.Value, pending, "recovery", "backup-code"))
	if w.Code != 303 {
		t.Fatalf("complete MFA %d %s", w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session")
	}
	session, err := f.a.Q.SessionByTokenHash(ctx, security.Hash(sessionCookie.Value))
	if err != nil || session.AuthTime != authTime {
		t.Fatalf("MFA lost authentication time: %d %v", session.AuthTime, err)
	}
}

func TestOAuthPositiveMaxAgeIsRecheckedAfterLogin(t *testing.T) {
	f := newOAuthFixture(t)
	fields := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "code_challenge": {strings.Repeat("v", 43)}, "max_age": {"30"}}
	r := httptest.NewRequest("GET", "/oauth2/authorize?"+fields.Encode(), nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	login, _ := url.Parse(w.Header().Get("Location"))
	continuation, _ := url.Parse(login.Query().Get("r"))
	if continuation.Query().Get("max_age") != "30" {
		t.Fatalf("continuation lost maximum age: %s", continuation)
	}
	// Model the time spent finishing MFA after the upstream callback.
	f.who.Session.AuthTime = time.Now().Add(-2 * time.Minute).Unix()
	r = httptest.NewRequest("GET", continuation.String(), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	next, _ := url.Parse(w.Header().Get("Location"))
	if next.Path != "/login" || next.Query().Get("max_age") != "30" {
		t.Fatalf("stale completed login authorized: %s", next)
	}
}

func TestOAuthRefreshUsesSessionAuthenticationTime(t *testing.T) {
	f := newOAuthFixture(t)
	status, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("issue %d %v", status, tokens)
	}
	// Existing upstream sessions migrate with unknown authentication time.
	if err := f.a.Q.SetSessionAuthTime(context.Background(), db.SetSessionAuthTimeParams{ID: f.who.Session.ID, AuthTime: 0}); err != nil {
		t.Fatal(err)
	}
	status, refreshed := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	if status != 200 {
		t.Fatalf("refresh %d %v", status, refreshed)
	}
	parts := strings.Split(refreshed["id_token"].(string), ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if _, exists := claims["auth_time"]; exists {
		t.Fatalf("refresh reused unverified authentication time: %v", claims)
	}
}
