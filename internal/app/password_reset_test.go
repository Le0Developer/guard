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

func TestBootstrapRequiresPasswordReset(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var required bool
	if err := a.Pool.QueryRow(ctx, "SELECT COALESCE((row_to_json(users)->>'force_password_reset')::boolean, false) FROM users WHERE id=0").Scan(&required); err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("new system account must require a password reset")
	}
	if _, err := a.Pool.Exec(ctx, "UPDATE users SET force_password_reset=false WHERE id=0"); err != nil {
		t.Fatal(err)
	}
	if err := a.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := a.Q.GetUser(ctx, 0)
	if err != nil || u.ForcePasswordReset {
		t.Fatalf("bootstrap changed existing account: %v", err)
	}
}

func TestForcedPasswordReset(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	hash, _ := security.HashPassword("temporary-password")
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "onboarding", Password: hash, Role: "Admin", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Pool.Exec(ctx, "UPDATE users SET force_password_reset=true WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	u, err = a.Q.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw := security.Token()
	login, err := a.Q.CreateLoginSession(ctx, db.CreateLoginSessionParams{TokenHash: security.Hash(raw), InternalToken: security.Token(), Provider: "password", State: []byte("{}"), RedirectUri: "/admin/users", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/login/password", nil)
	req.AddCookie(&http.Cookie{Name: "login_session", Value: raw})
	out := httptest.NewRecorder()
	if err = a.afterPrimary(out, req, u, login); err != nil {
		t.Fatal(err)
	}
	if out.Code != 303 || !strings.HasPrefix(out.Header().Get("Location"), "/password-reset?") {
		t.Fatalf("login bypassed reset: %d %s", out.Code, out.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, c := range out.Result().Cookies() {
		if c.Name == "session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("missing restricted session")
	}
	originalSessionRaw := session.Value
	row, err := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := a.sessionByID(ctx, a.Q, row.ID); err != nil || identity != nil {
		t.Fatalf("restricted session accepted by protocol validation: %v %v", identity, err)
	}
	h := a.Handler()
	request := func(method, path string, form url.Values, token string) *httptest.ResponseRecorder {
		var body *strings.Reader
		if form == nil {
			body = strings.NewReader("")
		} else {
			form.Set("csrf_token", token)
			body = strings.NewReader(form.Encode())
		}
		r := httptest.NewRequest(method, path, body)
		r.AddCookie(session)
		if method == "POST" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/", "/admin/users", "/oauth2/authorize", "/login/password", "/mfa"} {
		w := request("GET", path, nil, "")
		if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/password-reset?") {
			t.Fatalf("access before reset %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	resetURL := out.Header().Get("Location")
	page := request("GET", resetURL, nil, "")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Choose a new password") {
		t.Fatalf("reset page: %d %s", page.Code, page.Body.String())
	}
	csrfToken := ""
	for _, c := range page.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
		}
	}
	for _, form := range []url.Values{
		{"password": {"short"}, "confirm_password": {"short"}},
		{"password": {"replacement-password"}, "confirm_password": {"different-password"}},
		{"password": {"temporary-password"}, "confirm_password": {"temporary-password"}},
	} {
		if w := request("POST", resetURL, form, csrfToken); w.Code != 400 {
			t.Fatalf("invalid password accepted: %d %s", w.Code, w.Body.String())
		}
	}
	if w := request("POST", resetURL, url.Values{"password": {"replacement-password"}, "confirm_password": {"replacement-password"}}, "bad"); w.Code != 403 {
		t.Fatalf("CSRF: %d", w.Code)
	}
	secondRaw := security.Token()
	second, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(secondRaw), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	done := request("POST", resetURL, url.Values{"password": {"replacement-password"}, "confirm_password": {"replacement-password"}}, csrfToken)
	if done.Code != 303 || done.Header().Get("Location") != "/admin/users" {
		t.Fatalf("reset: %d %s %s", done.Code, done.Header().Get("Location"), done.Body.String())
	}
	for _, c := range done.Result().Cookies() {
		if c.Name == "session" {
			session = c
		}
	}
	current, err := a.Q.GetUser(ctx, u.ID)
	if err != nil || current.ForcePasswordReset || !security.VerifyPassword("replacement-password", current.Password) {
		t.Fatalf("password not updated: %v", err)
	}
	if _, err = a.Q.SessionByTokenHash(ctx, security.Hash(originalSessionRaw)); err == nil {
		t.Fatal("old session token still valid")
	}
	if _, err = a.Q.GetSession(ctx, second.ID); !notFound(err) {
		t.Fatalf("other session survived: %v", err)
	}
	if v, err := a.sessionByID(ctx, a.Q, row.ID); err != nil || v == nil {
		t.Fatalf("reset session not usable: %v", err)
	}
	if w := request("GET", "/", nil, ""); w.Code != 200 {
		t.Fatalf("home after reset: %d %s", w.Code, w.Body.String())
	}
}

func TestUpstreamLoginRequiresPasswordReset(t *testing.T) {
	f := newUpstreamFixture(t)
	f.a.Config.PasswordDisabled = true
	if _, err := f.a.Pool.Exec(context.Background(), "UPDATE users SET force_password_reset=true WHERE id=$1", f.user.ID); err != nil {
		t.Fatal(err)
	}
	c, q := f.begin(t)
	w := f.callback(t, c, q)
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/password-reset?") {
		t.Fatalf("upstream bypassed reset: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("no restricted upstream session")
	}
	h := f.a.Handler()
	r := httptest.NewRequest("GET", w.Header().Get("Location"), nil)
	r.AddCookie(session)
	page := httptest.NewRecorder()
	h.ServeHTTP(page, r)
	if page.Code != 200 {
		t.Fatalf("upstream reset page: %d", page.Code)
	}
	token := ""
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			token = cookie.Value
		}
	}
	form := url.Values{"password": {"new-local-password"}, "confirm_password": {"new-local-password"}, "csrf_token": {token}}
	r = httptest.NewRequest("POST", "/password-reset?r=https%3A%2F%2Fevil.example", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(session)
	done := httptest.NewRecorder()
	h.ServeHTTP(done, r)
	if done.Code != 303 || done.Header().Get("Location") != "/" {
		t.Fatalf("upstream reset failed: %d %s", done.Code, done.Body.String())
	}
	user, err := f.a.Q.GetUser(context.Background(), f.user.ID)
	if err != nil || user.ForcePasswordReset || !security.VerifyPassword("new-local-password", user.Password) {
		t.Fatalf("upstream local password not set: %v", err)
	}
}

func TestForcedPasswordResetAfterMFA(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	p := adminUserParams(u)
	p.ForcePasswordReset = true
	var err error
	u, err = a.Q.UpdateUser(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	sealed, err := a.mfaSeal(u.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateTotpAuthenticator(ctx, db.CreateTotpAuthenticatorParams{UserID: u.ID, Name: "phone", Secret: sealed, LastStep: -1}); err != nil {
		t.Fatal(err)
	}
	raw := security.Token()
	login, err := a.Q.CreateLoginSession(ctx, db.CreateLoginSessionParams{TokenHash: security.Hash(raw), InternalToken: security.Token(), Provider: "password", State: []byte("{}"), RedirectUri: "/", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/login/password", nil)
	r.AddCookie(&http.Cookie{Name: "login_session", Value: raw})
	w := httptest.NewRecorder()
	if err = a.afterPrimary(w, r, u, login); err != nil {
		t.Fatal(err)
	}
	if w.Code != 303 || w.Header().Get("Location") != "/login/mfa" {
		t.Fatalf("MFA skipped: %d %s", w.Code, w.Header().Get("Location"))
	}
	ticket := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			t.Fatal("session issued before MFA")
		}
		if c.Name == "mfa_pending" {
			ticket = c.Value
		}
	}
	w = httptest.NewRecorder()
	a.mfaCode(w, mfaTestRequest(raw, ticket, "totp", mfaTOTP(secret, time.Now().Unix()/30)))
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/password-reset?") {
		t.Fatalf("MFA bypassed reset: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

func TestAdminForcePasswordReset(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	request := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	form := url.Values{"username": {"new-user"}, "role": {"User"}, "password": {"temporary-password"}, "force_password_reset": {"on"}}
	if w := request("POST", "/admin/users", form); w.Code != 303 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	u, err := a.Q.UserByUsername(ctx, "new-user")
	if err != nil || !u.ForcePasswordReset {
		t.Fatalf("creation flag not saved: %v", err)
	}
	path := "/admin/users/" + fmt.Sprint(u.ID)
	if w := request("GET", path, nil); !strings.Contains(w.Body.String(), `name="force_password_reset" type="checkbox" checked`) {
		t.Fatal("flag missing from admin form")
	}
	form = url.Values{"username": {"new-user"}}
	if w := request("POST", path, form); w.Code != 303 {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	u, err = a.Q.GetUser(ctx, u.ID)
	if err != nil || u.ForcePasswordReset {
		t.Fatalf("flag not cleared: %v", err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(security.Token()), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	form.Set("force_password_reset", "on")
	if w := request("POST", path, form); w.Code != 303 {
		t.Fatalf("set: %d %s", w.Code, w.Body.String())
	}
	if _, err = a.Q.GetSession(ctx, s.ID); !notFound(err) {
		t.Fatalf("old session survived flag: %v", err)
	}
	form = url.Values{"password": {"another-temporary-password"}, "confirm_password": {"another-temporary-password"}, "force_password_reset": {"on"}}
	if w := request("POST", path+"/password", form); w.Code != 303 {
		t.Fatalf("admin reset: %d %s", w.Code, w.Body.String())
	}
	u, err = a.Q.GetUser(ctx, u.ID)
	if err != nil || !u.ForcePasswordReset || !security.VerifyPassword("another-temporary-password", u.Password) {
		t.Fatalf("reset flag/password not saved: %v", err)
	}
}
