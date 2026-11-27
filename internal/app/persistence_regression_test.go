package app

import (
	"context"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func failingInsert(t *testing.T, a *App, table string) {
	t.Helper()
	ctx := context.Background()
	_, err := a.Pool.Exec(ctx, `CREATE FUNCTION guard_test_reject_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected persistence failure'; END $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Pool.Exec(ctx, `CREATE TRIGGER guard_test_reject_insert BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION guard_test_reject_insert()`)
	if err != nil {
		t.Fatal(err)
	}
}
func TestOAuthFailsClosedWhenJournalCannotPersist(t *testing.T) {
	for _, table := range []string{"access_logs", "access_log_deliveries"} {
		t.Run(table, func(t *testing.T) {
			f := newOAuthFixture(t)
			ctx := context.Background()
			c := f.client
			c.DetailedLogging = true
			_, err := f.a.Q.UpdateClient(ctx, db.UpdateClientParams{ID: c.ID, Name: c.Name, Slug: c.Slug, ClientType: c.ClientType, ClientID: c.ClientID, ClientSecret: c.ClientSecret, SessionLifetimeS: c.SessionLifetimeS, RequirePkce: c.RequirePkce, DetailedLogging: true})
			if err != nil {
				t.Fatal(err)
			}
			f.a.Config.ExportURL = "https://collector.example.com"
			failingInsert(t, f.a, table)
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/test/.well-known/openid-configuration", nil))
			if w.Code != 503 || !strings.Contains(w.Body.String(), "access_journal_unavailable") {
				t.Fatalf("journal failure returned %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "authorization_endpoint") {
				t.Fatal("successful response leaked")
			}
		})
	}
}
func forwardFixture(t *testing.T) (*App, db.Client, db.User, db.Session) {
	t.Helper()
	a := testApp(t)
	ctx := context.Background()
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "forward-regression", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash("guard-browser"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Forward", Slug: "forward", ClientType: "ForwardAuth", ClientID: "forward", ClientSecret: "secret", SessionLifetimeS: 600, DetailedLogging: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: c.ID, RedirectUri: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return a, c, u, s
}
func forwardRequest(path, uri string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Uri", uri)
	return r
}
func TestForwardFailsClosedWhenJournalCannotPersist(t *testing.T) {
	for _, table := range []string{"access_logs", "access_log_deliveries"} {
		t.Run(table, func(t *testing.T) {
			a, c, u, s := forwardFixture(t)
			a.Config.ExportURL = "https://collector.example.com"
			_, err := a.Q.CreateForwardAuthSession(context.Background(), db.CreateForwardAuthSessionParams{ClientID: c.ID, UserID: u.ID, SessionID: s.ID, TokenHash: security.Hash("app-cookie"), Origin: "https://app.example.com", ExpiresAt: time.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			failingInsert(t, a, table)
			r := forwardRequest("/auth_request", "/private")
			r.AddCookie(&http.Cookie{Name: forwardCookie(c.ID, "https://app.example.com"), Value: "app-cookie"})
			w := httptest.NewRecorder()
			a.ForwardHandler().ServeHTTP(w, r)
			if w.Code != 503 {
				t.Fatalf("journal failure allowed %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("X-Guard-User-Id") != "" {
				t.Fatal("identity leaked on failure")
			}
		})
	}
}
func TestForwardAuthRequestCallbackAdapter(t *testing.T) {
	a, _, _, _ := forwardFixture(t)
	h := a.ForwardHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, forwardRequest("/auth_request", "/private"))
	if w.Code != 401 {
		t.Fatalf("start %d", w.Code)
	}
	binding := w.Result().Cookies()
	auth, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", auth.RequestURI(), nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "guard-browser"})
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("authorize %d %s", w.Code, w.Body.String())
	}
	callback, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	r = forwardRequest("/auth_request", callback.RequestURI())
	for _, c := range binding {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || w.Header().Get("Location") != "https://app.example.com/private" {
		t.Fatalf("callback subrequest %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !strings.Contains(cookies[0].Name, "session") {
		t.Fatalf("expected only application cookie, got %v", cookies)
	}
	r = forwardRequest("/auth_request", "/private")
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("verification %d %s", w.Code, w.Body.String())
	}
}
