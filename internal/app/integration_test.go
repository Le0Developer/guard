package app

import (
	"context"
	"encoding/base64"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	dsn := os.Getenv("GUARD_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GUARD_TEST_DATABASE_URL for PostgreSQL integration tests")
	}
	ctx := context.Background()
	base, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := "test_" + strings.ToLower(security.Token()[:12])
	schema = strings.ReplaceAll(schema, "-", "a")
	_, err = base.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize())
	if err != nil {
		t.Fatal(err)
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer cleanup.Close()
		if _, err = cleanup.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if err = db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	a, err := New(pool, Config{Domain: "http://localhost:4444", ReportLimit: 600, MFAEncryptionKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestPasswordLoginSessionAndLogout(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	hash, _ := security.HashPassword("correct horse battery staple")
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "alice", Password: hash, Role: "User", WebauthnUserID: []byte(security.Token())})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "/login/password?r=%2F", nil))
	if get.Code != 200 {
		t.Fatalf("login page: %d %s", get.Code, get.Body.String())
	}
	cookies := get.Result().Cookies()
	var loginRaw, csrfRaw string
	for _, c := range cookies {
		switch c.Name {
		case "login_session":
			loginRaw = c.Value
		case "csrf_token":
			csrfRaw = c.Value
		}
	}
	login, err := a.Q.LoginSessionByTokenHash(ctx, security.Hash(loginRaw))
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"email": {"alice"}, "password": {"correct horse battery staple"}, "csrf_token": {csrfRaw}, "login_token": {login.InternalToken}}
	req := httptest.NewRequest("POST", "/login/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 303 {
		t.Fatalf("login: %d %s", out.Code, out.Body.String())
	}
	var session *http.Cookie
	for _, c := range out.Result().Cookies() {
		if c.Name == "session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("missing session")
	}
	s, err := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
	if err != nil || s.UserID != u.ID {
		t.Fatalf("session: %+v %v", s, err)
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(session)
	home := httptest.NewRecorder()
	h.ServeHTTP(home, req)
	if home.Code != 200 || !strings.Contains(home.Body.String(), "alice") {
		t.Fatalf("home %d %s", home.Code, home.Body.String())
	}
	for _, c := range home.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfRaw = c.Value
		}
	}
	req = httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf_token": {csrfRaw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	out = httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 303 {
		t.Fatalf("logout %d", out.Code)
	}
	if _, err = a.Q.GetSession(ctx, s.ID); !notFound(err) {
		t.Fatalf("session survives logout: %v", err)
	}
}
func TestSessionExpiryAndDisabledUser(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "disabled", Role: "User", Disabled: true, WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash("disabled-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	v, err := a.sessionByID(ctx, a.Q, s.ID)
	if err != nil || v != nil {
		t.Fatalf("accepted disabled user %v %v", v, err)
	}
}

func TestGroupNameUniquenessIsEnforcedByDatabase(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	if _, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Engineering"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "engineering"}); err == nil {
		t.Fatal("case-insensitive duplicate group name accepted")
	}
}
