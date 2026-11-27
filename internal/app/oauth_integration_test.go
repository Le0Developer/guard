package app

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type oauthFixture struct {
	a      *App
	h      http.Handler
	client db.Client
	who    *identity
}

func newOAuthFixture(t *testing.T) oauthFixture {
	t.Helper()
	a := testApp(t)
	ctx := context.Background()
	u, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "oauth-alice", Role: "User", Email: "alice@example.com", WebauthnUserID: []byte(security.Token())})
	if e != nil {
		t.Fatal(e)
	}
	s, e := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(security.Token()), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	c, e := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Test", Slug: "test", ClientType: "Oidc", ClientID: "client", ClientSecret: "secret", SessionLifetimeS: 1800, RequirePkce: true})
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.Q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: c.ID, RedirectUri: "https://client.example/callback"})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	a.registerOAuth(mux)
	return oauthFixture{a, mux, c, &identity{User: u, Session: s}}
}
func (f oauthFixture) code(t *testing.T) string { return f.codeScope(t, "openid profile email") }
func (f oauthFixture) codeScope(t *testing.T, scope string) string {
	t.Helper()
	v := strings.Repeat("v", 43)
	fields := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "scope": {scope}, "nonce": {"nonce"}, "state": {"state"}, "code_challenge": {security.Hash(v)}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest("GET", "/oauth2/authorize?"+fields.Encode(), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	u, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("code") == "" || u.Query().Get("state") != "state" {
		t.Fatalf("callback: %s", u)
	}
	return u.Query().Get("code")
}
func (f oauthFixture) post(path string, fields url.Values) (int, map[string]any) {
	r := httptest.NewRequest("POST", path, strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("client", "secret")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	v := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v
}
func oauthCodeFields(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {strings.Repeat("v", 43)}}
}
func (f oauthFixture) info(access string) int {
	r := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w.Code
}
func TestOAuthCodePKCEAndReplay(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t)
	fields := oauthCodeFields(code)
	fields.Set("code_verifier", strings.Repeat("x", 43))
	status, out := f.post("/oauth2/token", fields)
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier %d %v", status, out)
	}
	status, out = f.post("/oauth2/token", oauthCodeFields(code))
	if status != 200 {
		t.Fatalf("redeem %d %v", status, out)
	}
	access := out["access_token"].(string)
	if f.info(access) != 200 {
		t.Fatal("access token rejected")
	}
	jwt := out["id_token"].(string)
	parts := strings.Split(jwt, ".")
	ks, e := f.a.Q.SigningKeysByClientId(context.Background(), f.client.ID)
	if e != nil || len(ks) != 1 {
		t.Fatalf("signing keys %v %v", ks, e)
	}
	k, e := x509.ParsePKCS1PrivateKey(ks[0].Key)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e = rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, hash[:], sig); e != nil {
		t.Fatal(e)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := map[string]any{}
	_ = json.Unmarshal(payload, &claims)
	if claims["nonce"] != "nonce" || claims["aud"] != "client" || claims["iss"] != f.a.Config.Domain+"/oauth2/test" {
		t.Fatalf("JWT claims %v", claims)
	}
	status, out = f.post("/oauth2/token", oauthCodeFields(code))
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("replayed code %d %v", status, out)
	}
	if f.info(access) != 401 {
		t.Fatal("code replay did not revoke token")
	}
}
func TestOAuthConcurrentRefreshReplayRevokesFamily(t *testing.T) {
	f := newOAuthFixture(t)
	status, out := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("token %d %v", status, out)
	}
	refresh := out["refresh_token"].(string)
	type result struct {
		status int
		v      map[string]any
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			s, v := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
			results <- result{s, v}
		})
	}
	wg.Wait()
	close(results)
	success, invalid := 0, 0
	var access string
	for r := range results {
		if r.status == 200 {
			success++
			access = r.v["access_token"].(string)
		} else if r.status == 400 && r.v["error"] == "invalid_grant" {
			invalid++
		} else {
			t.Fatalf("unexpected response %d %v", r.status, r.v)
		}
	}
	if success != 1 || invalid != 1 {
		t.Fatalf("race outcomes %d %d", success, invalid)
	}
	if f.info(access) != 401 {
		t.Fatal("refresh replay did not revoke committed descendant")
	}
}
func TestOAuthRevocationAndSessionValidation(t *testing.T) {
	f := newOAuthFixture(t)
	status, out := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("token %d %v", status, out)
	}
	access, refresh := out["access_token"].(string), out["refresh_token"].(string)
	status, _ = f.post("/oauth2/revoke", url.Values{"token": {access}})
	if status != 200 || f.info(access) != 401 {
		t.Fatal("revoke failed")
	}
	status, out = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != 400 {
		t.Fatalf("revoked refresh accepted %v", out)
	}
	code := f.code(t)
	if e := f.a.Q.DeleteSession(context.Background(), f.who.Session.ID); e != nil {
		t.Fatal(e)
	}
	status, out = f.post("/oauth2/token", oauthCodeFields(code))
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("dead session grant %d %v", status, out)
	}
}

func TestOAuthPromptAndRedirectValidation(t *testing.T) {
	f := newOAuthFixture(t)
	base := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example/callback"}, "response_type": {"code"}, "code_challenge": {strings.Repeat("v", 43)}, "prompt": {"none"}, "state": {"keep"}}
	r := httptest.NewRequest("GET", "/oauth2/authorize?"+base.Encode(), nil)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 303 || u.Query().Get("error") != "login_required" || u.Query().Get("state") != "keep" {
		t.Fatalf("prompt none: %d %s", w.Code, w.Header().Get("Location"))
	}
	base.Set("max_age", "0")
	r = httptest.NewRequest("GET", "/oauth2/authorize?"+base.Encode(), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	u, _ = url.Parse(w.Header().Get("Location"))
	if u.Query().Get("error") != "login_required" {
		t.Fatalf("max_age zero did not force login: %s", u)
	}
	base.Set("prompt", "login")
	r = httptest.NewRequest("GET", "/oauth2/authorize?"+base.Encode(), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	u, _ = url.Parse(w.Header().Get("Location"))
	continuation, _ := url.Parse(u.Query().Get("r"))
	if w.Code != 303 || u.Path != "/login" || (continuation.Query().Has("prompt") || continuation.Query().Has("max_age")) {
		t.Fatalf("forced login: %d %s", w.Code, u)
	}
	base.Set("redirect_uri", "https://attacker.example/")
	r = httptest.NewRequest("GET", "/oauth2/authorize?"+base.Encode(), nil)
	w = httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("unregistered callback redirect: %d", w.Code)
	}
}

func TestOAuthPostAuthenticationAndDisabledUser(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t)
	fields := oauthCodeFields(code)
	fields.Set("client_id", "client")
	fields.Set("client_secret", "wrong")
	post := func() (int, map[string]any) {
		r := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		v := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return w.Code, v
	}
	status, v := post()
	if status != 401 || v["error"] != "invalid_client" {
		t.Fatalf("bad secret %d %v", status, v)
	}
	fields.Set("client_secret", "secret")
	status, v = post()
	if status != 200 {
		t.Fatalf("post auth %d %v", status, v)
	}
	access, refresh := v["access_token"].(string), v["refresh_token"].(string)
	u := f.who.User
	_, e := f.a.Q.UpdateUser(context.Background(), db.UpdateUserParams{ID: u.ID, Username: u.Username, Email: u.Email, Password: u.Password, Role: u.Role, Disabled: true, WebauthnUserID: u.WebauthnUserID})
	if e != nil {
		t.Fatal(e)
	}
	if f.info(access) != 401 {
		t.Fatal("disabled user access accepted")
	}
	status, v = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != 400 || v["error"] != "invalid_grant" {
		t.Fatalf("disabled refresh %d %v", status, v)
	}
}
func TestOAuthRefreshScopeCannotExpand(t *testing.T) {
	f := newOAuthFixture(t)
	status, v := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("grant %d %v", status, v)
	}
	status, v = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {v["refresh_token"].(string)}, "scope": {"openid"}})
	if status != 200 || v["scope"] != "openid" {
		t.Fatalf("reduction %d %v", status, v)
	}
	status, v = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {v["refresh_token"].(string)}, "scope": {"openid email"}})
	if status != 400 || v["error"] != "invalid_scope" {
		t.Fatalf("expansion %d %v", status, v)
	}
}

func TestOAuthPermissionChangesInvalidateGrants(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t)
	status, v := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("grant %d %v", status, v)
	}
	access, refresh := v["access_token"].(string), v["refresh_token"].(string)
	ctx := context.Background()
	g, e := f.a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "restricted"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.a.Q.CreateClientAccessRule(ctx, db.CreateClientAccessRuleParams{ClientID: f.client.ID, GroupID: g.ID, AccessControl: "Allow"})
	if e != nil {
		t.Fatal(e)
	}
	if f.info(access) != 401 {
		t.Fatal("permissions not rechecked for access")
	}
	status, v = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != 400 || v["error"] != "invalid_grant" {
		t.Fatalf("permissions not rechecked for refresh %d %v", status, v)
	}
	status, v = f.post("/oauth2/token", oauthCodeFields(code))
	if status != 400 || v["error"] != "invalid_grant" {
		t.Fatalf("permissions not rechecked for code %d %v", status, v)
	}
}

func TestOIDCSubjectPersistenceAndEndpoints(t *testing.T) {
	f := introspectionFixture(t)
	ctx := context.Background()
	subject := f.a.oidcSubject(f.client, f.who.User.ID)
	restarted, err := New(f.a.Pool, f.a.Config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.oidcSubject(f.client, f.who.User.ID) != subject {
		t.Fatal("subject changed on restart")
	}
	decode := func(raw string) map[string]any {
		t.Helper()
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatal("invalid JWT")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err = json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		return claims
	}
	status, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("mint: %d %v", status, tokens)
	}
	if decode(tokens["id_token"].(string))["sub"] != subject {
		t.Fatal("ID token subject mismatch")
	}
	r := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	var info map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &info); err != nil || w.Code != 200 || info["sub"] != subject || info["username"] != f.who.User.Username {
		t.Fatalf("UserInfo mismatch: %d %v %v", w.Code, info, err)
	}
	status, info = f.post("/oauth2/introspect", url.Values{"token": {tokens["access_token"].(string)}})
	if status != 200 || info["sub"] != subject {
		t.Fatalf("introspection mismatch: %d %v", status, info)
	}
	status, tokens = f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	if status != 200 || decode(tokens["id_token"].(string))["sub"] != subject {
		t.Fatalf("refresh mismatch: %d %v", status, tokens)
	}
	logout, err := f.a.logoutJWT(ctx, f.a.Q, f.client, db.LogoutDelivery{UserID: f.who.User.ID, Sid: "session", Jti: "logout"})
	if err != nil {
		t.Fatal(err)
	}
	if decode(logout)["sub"] != subject {
		t.Fatal("logout subject mismatch")
	}
}
