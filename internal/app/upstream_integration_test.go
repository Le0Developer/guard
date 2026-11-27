package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type upstreamFixture struct {
	a               *App
	p               db.UpstreamProvider
	user            db.User
	key             *rsa.PrivateKey
	server          *httptest.Server
	nonce           atomic.Value
	userinfoSubject atomic.Value
	issuedAt        int64
}

func upstreamSigned(t *testing.T, key *rsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": typ})
	b, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func newUpstreamFixture(t *testing.T) *upstreamFixture {
	t.Helper()
	f := &upstreamFixture{a: testApp(t), issuedAt: time.Now().Add(-2 * time.Second).Unix()}
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.nonce.Store("")
	f.userinfoSubject.Store("remote-alice")
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
		case "/token":
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != "upstream-client" || secret != "upstream-secret" || r.FormValue("client_secret") != "" || r.FormValue("client_id") != "" {
				t.Error("missing upstream client authentication")
			}
			id := upstreamSigned(t, f.key, "JWT", map[string]any{"iss": f.server.URL, "aud": "upstream-client", "sub": "remote-alice", "sid": "upstream-session", "iat": f.issuedAt, "exp": time.Now().Add(5 * time.Minute).Unix(), "nonce": f.nonce.Load().(string)})
			json.NewEncoder(w).Encode(map[string]string{"access_token": "upstream-access", "id_token": id})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]any{"sub": f.userinfoSubject.Load().(string), "email": "alice@example.com", "email_verified": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	f.p, err = f.a.Q.CreateUpstreamProvider(context.Background(), db.CreateUpstreamProviderParams{Slug: "work", Name: "Work", Issuer: f.server.URL, AuthorizeUrl: f.server.URL + "/authorize", TokenUrl: f.server.URL + "/token", UserinfoUrl: f.server.URL + "/userinfo", JwksUrl: f.server.URL + "/keys", ClientID: "upstream-client", ClientSecret: "upstream-secret", Scopes: "openid profile email", Pkce: true, SigningAlg: "RS256", Enabled: true, BackchannelLogoutEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	f.user, err = f.a.Q.CreateUser(context.Background(), db.CreateUserParams{Username: "local-alice", Email: "alice@example.com", Role: "User", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *upstreamFixture) begin(t *testing.T) (*http.Cookie, url.Values) {
	t.Helper()
	r := httptest.NewRequest("GET", "/login/work", nil)
	r.SetPathValue("method", f.p.Slug)
	w := httptest.NewRecorder()
	f.a.login(w, r)
	if w.Code != 303 {
		t.Fatalf("begin %d %s", w.Code, w.Body.String())
	}
	u, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	if u.Query().Get("nonce") == "" {
		t.Fatal("missing OIDC nonce")
	}
	f.nonce.Store(u.Query().Get("nonce"))
	for _, c := range w.Result().Cookies() {
		if c.Name == "login_session" {
			return c, u.Query()
		}
	}
	t.Fatal("no login cookie")
	return nil, nil
}
func (f *upstreamFixture) callback(t *testing.T, c *http.Cookie, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/login/work/callback?"+url.Values{"state": {q.Get("state")}, "code": {"code"}}.Encode(), nil)
	r.SetPathValue("method", f.p.Slug)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	f.a.upstreamCallback(w, r)
	return w
}
func (f *upstreamFixture) login(t *testing.T) (db.Session, *http.Cookie) {
	t.Helper()
	c, q := f.begin(t)
	w := f.callback(t, c, q)
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("callback %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	for _, s := range w.Result().Cookies() {
		if s.Name == "session" {
			session, e := f.a.Q.SessionByTokenHash(context.Background(), security.Hash(s.Value))
			if e != nil {
				t.Fatal(e)
			}
			return session, s
		}
	}
	t.Fatal("no Guard session")
	return db.Session{}, nil
}
func (f *upstreamFixture) logout(t *testing.T, subject, sid, jti string) *httptest.ResponseRecorder {
	t.Helper()
	claims := map[string]any{"iss": f.p.Issuer, "aud": f.p.ClientID, "iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(), "jti": jti, "events": map[string]any{logoutEvent: map[string]any{}}}
	if subject != "" {
		claims["sub"] = subject
	}
	if sid != "" {
		claims["sid"] = sid
	}
	token := upstreamSigned(t, f.key, "logout+jwt", claims)
	r := httptest.NewRequest("POST", "/login/work/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	return w
}
func TestUpstreamProvidersComeFromDatabase(t *testing.T) {
	f := newUpstreamFixture(t)
	w := httptest.NewRecorder()
	f.a.login(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Work") {
		t.Fatalf("database provider not shown %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), f.p.ClientSecret) {
		t.Fatal("client secret leaked")
	}
	s, _ := f.login(t)
	b, e := f.a.Q.GetUpstreamSession(context.Background(), s.ID)
	if e != nil || b.ProviderID != f.p.ID || b.Subject != "remote-alice" || b.Sid != "upstream-session" {
		t.Fatalf("binding missing %v %v", b, e)
	}
}
func TestUpstreamLogoutOnlyRevokesProviderSessionsAndQueuesDownstream(t *testing.T) {
	f := newUpstreamFixture(t)
	s, _ := f.login(t)
	ctx := context.Background()
	local, e := f.a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: f.user.ID, TokenHash: security.Hash("local-password"), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	c, e := f.a.Q.CreateClient(ctx, db.CreateClientParams{Name: "App", Slug: "downstream", ClientType: "Oidc", ClientID: "downstream", ClientSecret: "secret", SessionLifetimeS: 600})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.a.Q.SetClientBackchannelLogout(ctx, db.SetClientBackchannelLogoutParams{ID: c.ID, BackchannelLogoutUri: "https://app.example.com/logout"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.a.oauthSID(ctx, f.a.Q, c, &identity{User: f.user, Session: s})
	if e != nil {
		t.Fatal(e)
	}
	w := f.logout(t, "remote-alice", "upstream-session", "event1")
	if w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body.String())
	}
	if _, e = f.a.Q.GetSession(ctx, s.ID); !notFound(e) {
		t.Fatalf("upstream session not revoked %v", e)
	}
	if _, e = f.a.Q.GetSession(ctx, local.ID); e != nil {
		t.Fatal("password session revoked")
	}
	deliveries, e := f.a.Q.ListLogoutDeliveries(ctx)
	if e != nil || len(deliveries) != 1 {
		t.Fatalf("downstream logout not queued %v %v", deliveries, e)
	}
	if w = f.logout(t, "remote-alice", "upstream-session", "event1"); w.Code != 200 {
		t.Fatalf("idempotent logout %d", w.Code)
	}
}
func TestUpstreamLogoutBlocksDelayedCallback(t *testing.T) {
	f := newUpstreamFixture(t)
	c, q := f.begin(t)
	if w := f.logout(t, "remote-alice", "upstream-session", "before-callback"); w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body.String())
	}
	w := f.callback(t, c, q)
	if w.Code == 303 {
		t.Fatal("delayed upstream callback resurrected session")
	}
	sessions, e := f.a.Q.SessionsByUserId(context.Background(), f.user.ID)
	if e != nil || len(sessions) != 0 {
		t.Fatalf("resurrected %v %v", sessions, e)
	}
}
func TestUpstreamCallbackRejectsUserinfoSubjectMismatch(t *testing.T) {
	f := newUpstreamFixture(t)
	f.userinfoSubject.Store("other-subject")
	c, q := f.begin(t)
	w := f.callback(t, c, q)
	if w.Code != 403 {
		t.Fatalf("userinfo/IDtoken substitution accepted %d %s", w.Code, w.Body.String())
	}
}
func TestOIDCEnvironmentVariablesAreRemoved(t *testing.T) {
	_, e := configFromEnv(func(k string) string {
		switch k {
		case "DOMAIN":
			return "http://localhost:4444"
		case "DATABASE_URL":
			return "postgres://localhost/guard"
		case "OIDC_PROVIDER_NAME":
			return "broken-provider"
		case "OIDC_CLIENT_ID":
			return "old-env-client"
		}
		return ""
	})
	if e != nil {
		t.Fatalf("legacy OIDC environment setup still loaded: %v", e)
	}
}

func TestUpstreamLogoutRevokesPendingMFA(t *testing.T) {
	f := newUpstreamFixture(t)
	ctx := context.Background()
	secret, err := f.a.mfaSeal(f.user.ID, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.CreateTotpAuthenticator(ctx, db.CreateTotpAuthenticatorParams{UserID: f.user.ID, Name: "Phone", Secret: secret, LastStep: -1}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{UserID: f.user.ID, Hash: mfaRecoveryHash(f.user.ID, "backup-code")}); err != nil {
		t.Fatal(err)
	}
	c, q := f.begin(t)
	w := f.callback(t, c, q)
	if w.Code != 303 || w.Header().Get("Location") != "/login/mfa" {
		t.Fatalf("missing MFA challenge %d %s", w.Code, w.Body.String())
	}
	var pending string
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "mfa_pending" {
			pending = cookie.Value
		}
	}
	if pending == "" {
		t.Fatal("no MFA pending cookie")
	}
	w = f.logout(t, "remote-alice", "upstream-session", "during-mfa")
	if w.Code != 200 {
		t.Fatalf("logout during MFA %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	f.a.mfaCode(w, mfaTestRequest(c.Value, pending, "recovery", "backup-code"))
	if w.Code == 303 {
		t.Fatal("MFA completion resurrected upstream session")
	}
	sessions, err := f.a.Q.SessionsByUserId(ctx, f.user.ID)
	if err != nil || len(sessions) != 0 {
		t.Fatalf("unexpected sessions %v %v", sessions, err)
	}
}
func TestUpstreamSubjectLogoutDoesNotCrossProviders(t *testing.T) {
	f := newUpstreamFixture(t)
	s1, _ := f.login(t)
	s2, _ := f.login(t)
	ctx := context.Background()
	p, err := f.a.Q.CreateUpstreamProvider(ctx, db.CreateUpstreamProviderParams{Slug: "other", Name: "Other", Issuer: f.p.Issuer, AuthorizeUrl: f.p.AuthorizeUrl, TokenUrl: f.p.TokenUrl, UserinfoUrl: f.p.UserinfoUrl, JwksUrl: f.p.JwksUrl, ClientID: "different-upstream-client", ClientSecret: "secret", Scopes: "openid email", SigningAlg: "RS256", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	s3, err := f.a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: f.user.ID, TokenHash: security.Hash("other-provider"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.Q.BindUpstreamSession(ctx, db.BindUpstreamSessionParams{SessionID: s3.ID, ProviderID: p.ID, Subject: "remote-alice", Sid: "upstream-session", ProviderRevision: p.Revision, TokenIssuedAt: f.issuedAt}); err != nil {
		t.Fatal(err)
	}
	w := f.logout(t, "remote-alice", "", "subject-logout")
	if w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body.String())
	}
	for _, s := range []db.Session{s1, s2} {
		if _, err = f.a.Q.GetSession(ctx, s.ID); !notFound(err) {
			t.Fatal("matching subject session remains")
		}
	}
	if _, err = f.a.Q.GetSession(ctx, s3.ID); err != nil {
		t.Fatal("another provider's session revoked")
	}
}
func TestUpstreamLogoutRejectsIDTokenAndWrongSignature(t *testing.T) {
	f := newUpstreamFixture(t)
	s, _ := f.login(t)
	base := map[string]any{"iss": f.p.Issuer, "aud": f.p.ClientID, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "sub": "remote-alice", "sid": "upstream-session", "nonce": "some-login-nonce"}
	id := upstreamSigned(t, f.key, "JWT", base)
	for _, raw := range []string{id, id[:len(id)-3] + "aaa"} {
		r := httptest.NewRequest("POST", "/login/work/backchannel-logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid logout accepted %d %s", w.Code, w.Body.String())
		}
	}
	if _, err := f.a.Q.GetSession(context.Background(), s.ID); err != nil {
		t.Fatal("invalid logout revoked session")
	}
}
func TestUpstreamLogoutRollsBackIfDownstreamQueueFails(t *testing.T) {
	f := newUpstreamFixture(t)
	s, _ := f.login(t)
	ctx := context.Background()
	c, err := f.a.Q.CreateClient(ctx, db.CreateClientParams{Name: "App", Slug: "app", ClientType: "Oidc", ClientID: "app", ClientSecret: "secret", SessionLifetimeS: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.SetClientBackchannelLogout(ctx, db.SetClientBackchannelLogoutParams{ID: c.ID, BackchannelLogoutUri: "https://app.example.com/logout"}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.oauthSID(ctx, f.a.Q, c, &identity{User: f.user, Session: s}); err != nil {
		t.Fatal(err)
	}
	failingInsert(t, f.a, "logout_deliveries")
	w := f.logout(t, "remote-alice", "upstream-session", "retry-after-failure")
	if w.Code != 503 {
		t.Fatalf("queue failure should503: %d %s", w.Code, w.Body.String())
	}
	if _, err = f.a.Q.GetSession(ctx, s.ID); err != nil {
		t.Fatal("failed queue partially revoked session")
	}
	if _, err = f.a.Pool.Exec(ctx, "DROP TRIGGER guard_test_reject_insert ON logout_deliveries"); err != nil {
		t.Fatal(err)
	}
	w = f.logout(t, "remote-alice", "upstream-session", "retry-after-failure")
	if w.Code != 200 {
		t.Fatalf("retry %d %s", w.Code, w.Body.String())
	}
	if _, err = f.a.Q.GetSession(ctx, s.ID); !notFound(err) {
		t.Fatal("successful retry did not revoke")
	}
}

func TestUpstreamMFARechecksMatchedAccount(t *testing.T) {
	for _, mode := range []string{"email_changed", "ambiguous_email"} {
		t.Run(mode, func(t *testing.T) {
			f := newUpstreamFixture(t)
			ctx := context.Background()
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
			cookie, q := f.begin(t)
			w := f.callback(t, cookie, q)
			if w.Code != 303 || w.Header().Get("Location") != "/login/mfa" {
				t.Fatalf("start MFA %d %s", w.Code, w.Body.String())
			}
			var pending string
			for _, c := range w.Result().Cookies() {
				if c.Name == "mfa_pending" {
					pending = c.Value
				}
			}
			if mode == "email_changed" {
				params := adminUserParams(f.user)
				params.Email = "changed@example.com"
				_, err = f.a.Q.UpdateUser(ctx, params)
			} else {
				_, err = f.a.Q.CreateUser(ctx, db.CreateUserParams{Username: "duplicate", Email: f.user.Email, Role: "User", WebauthnUserID: []byte(security.Token())})
			}
			if err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			f.a.mfaCode(w, mfaTestRequest(cookie.Value, pending, "recovery", "backup-code"))
			if w.Code == 303 {
				t.Fatal("issued session for changed/ambiguous upstream account match")
			}
			sessions, err := f.a.Q.SessionsByUserId(ctx, f.user.ID)
			if err != nil || len(sessions) != 0 {
				t.Fatalf("unexpected session %v %v", sessions, err)
			}
		})
	}
}
