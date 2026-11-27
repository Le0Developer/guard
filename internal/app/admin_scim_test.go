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

func TestAdminSCIMConfiguration(t *testing.T) {
	a, c, u, _ := setupSCIM(t)
	ctx := context.Background()
	u.Role = "Admin"
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	path := fmt.Sprintf("/admin/clients/%d/scim", c.ID)
	request := func(method, route string, form url.Values, role string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, route, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if role != "" {
			actor := u
			actor.Role = role
			r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, role := range []string{"", "User"} {
		w := request("GET", path, nil, role)
		if w.Code != 303 && w.Code != 403 {
			t.Fatalf("authorization %s %d", role, w.Code)
		}
	}
	w := request("GET", path, nil, "Admin")
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-secret") || !strings.Contains(w.Body.String(), "Sync now") {
		t.Fatalf("SCIM page: %d %s", w.Code, w.Body.String())
	}
	old, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	w = request("POST", path, url.Values{"endpoint": {old.Endpoint}, "enabled": {"on"}}, "Admin")
	if w.Code != 303 {
		t.Fatalf("blank-preserve %d %s", w.Code, w.Body.String())
	}
	next, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	if next.Secret != old.Secret {
		t.Fatal("blank secret replaced stored credential")
	}
	w = request("POST", path, url.Values{"endpoint": {"https://new.example.org/scim"}, "enabled": {"on"}}, "Admin")
	if w.Code != 422 {
		t.Fatalf("endpoint reused old secret %d", w.Code)
	}
	w = request("POST", path, url.Values{"endpoint": {"https://new.example.org/scim"}, "secret": {"replacement"}, "enabled": {"on"}}, "Admin")
	if w.Code != 303 {
		t.Fatalf("replacement %d %s", w.Code, w.Body.String())
	}
	next, _ = a.Q.GetSCIMConfig(ctx, c.ID)
	if next.Generation != old.Generation+1 || next.LeaseToken != "" {
		t.Fatal("endpoint generation not replaced")
	}
	if raw, err := a.scimOpen(c.ID, next.Secret); err != nil || raw != "replacement" {
		t.Fatal("credential not replaced")
	}
	w = request("POST", path+"/sync", nil, "Admin")
	if w.Code != 303 {
		t.Fatalf("sync %d", w.Code)
	}
	rows, err := a.Q.ListAuditLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.Contains(string(row.Data), "replacement") || strings.Contains(string(row.Data), "test-secret") {
			t.Fatal("audit leaked secret")
		}
	}
}
func TestAdminSCIMCSRF(t *testing.T) {
	a, c, u, _ := setupSCIM(t)
	ctx := context.Background()
	if _, err := a.Pool.Exec(ctx, `UPDATE users SET role='Admin' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	token := "admin-scim-session"
	if _, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(token), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/admin/clients/%d/scim", c.ID)
	r := httptest.NewRequest("POST", path, strings.NewReader("endpoint=https%3A%2F%2Fexample.org%2Fscim&secret=leak&enabled=on"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "session", Value: token})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF accepted %d", w.Code)
	}
	cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	if cfg.Endpoint == "https://example.org/scim" {
		t.Fatal("CSRF changed configuration")
	}
}
