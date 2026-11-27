package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/le0developer/guard/internal/db"
)

// Missing validation must reject unsafe callbacks before any client is written.
func TestAdminBackchannelInvalidURI(t *testing.T) {
	a := testApp(t)
	actor, err := a.Q.CreateUser(context.Background(), db.CreateUserParams{Username: "admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://app.example/logout", "https://user:pass@app.example/logout", "https://app.example/logout#fragment", "https://*.example/logout", "/logout", "https://app.example/\nlogout", "https://app.example/" + strings.Repeat("x", 2048)} {
		r := httptest.NewRequest("POST", "/admin/clients", nil)
		r.PostForm = url.Values{"name": {"Bad"}, "client_type": {"Oidc"}, "session_lifetime_s": {"3600"}, "backchannel_logout_uri": {raw}}
		if err := a.adminWriteClient(httptest.NewRecorder(), r, &identity{User: actor}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

// Missing settings writes, rotation resets, or a type switch retaining callbacks break this lifecycle.
func TestAdminBackchannelPersistedLifecycle(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "logout-admin", Role: "Admin", WebauthnUserID: []byte{1}})
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
	form := url.Values{"name": {"App"}, "client_type": {"Oidc"}, "session_lifetime_s": {"3600"}, "backchannel_logout_uri": {"https://app.example/logout"}, "backchannel_logout_session_required": {"on"}}
	if w := request("POST", "/admin/clients", form); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	clients, err := a.Q.ListClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatal(clients, err)
	}
	c := clients[0]
	path := fmt.Sprintf("/admin/clients/%d", c.ID)
	check := func(uri string, required bool) {
		t.Helper()
		c, err = a.Q.GetClient(ctx, c.ID)
		if err != nil || c.BackchannelLogoutUri != uri || c.BackchannelLogoutSessionRequired != required {
			t.Fatalf("settings: %+v %v", c, err)
		}
	}
	check("https://app.example/logout", true)
	if w := request("GET", path, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `name="backchannel_logout_uri"`) || !strings.Contains(w.Body.String(), `value="https://app.example/logout"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	form.Set("backchannel_logout_uri", "http://[::1]:8000/logout")
	form.Del("backchannel_logout_session_required")
	if w := request("POST", path, form); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	check("http://[::1]:8000/logout", false)
	if w := request("POST", path+"/rotate-secret", url.Values{"confirm": {"rotate"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	check("http://[::1]:8000/logout", false)
	form.Set("client_type", "ForwardAuth")
	if w := request("POST", path, form); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	check("", false)
}

func TestValidateLogoutURIDevelopment(t *testing.T) {
	for _, raw := range []string{"", "https://app.example/logout?tenant=one", "http://localhost:8000/logout", "http://127.0.0.1/logout", "http://[::1]/logout"} {
		if err := validateLogoutURI(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://localhost.example/logout", "http://127.0.0.1.example/logout", "http://192.168.1.1/logout", "https:///logout", "https://app.example/logout#", "https://app.example/logout\x7f", "https://example.com/a b", "https://example.com/a\\b", "https://example.com/a\u00a0b", "https://example.com:65536/logout", "https://example.com:0/logout", "https://example.com:/logout"} {
		if err := validateLogoutURI(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
