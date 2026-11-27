package app

import (
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthParameters(t *testing.T) {
	if oauthUnique(url.Values{"x": {"1", "2"}}) {
		t.Fatal("duplicates accepted")
	}
	if !oauthUnique(url.Values{"x": {"1"}}) {
		t.Fatal("valid rejected")
	}
}
func TestOAuthPKCE(t *testing.T) {
	v := strings.Repeat("a", 43)
	if !oauthPKCE(v, v, "plain") || oauthPKCE("short", "short", "plain") || oauthPKCE(v, v, "bad") {
		t.Fatal("PKCE boundary")
	}
}

func TestOAuthFormRejectsAmbiguity(t *testing.T) {
	for _, tc := range []struct{ target, body string }{{"/oauth2/token", "code=x&code=y"}, {"/oauth2/token?code=x", "code=y"}, {"/oauth2/token", "bad=%zz"}} {
		r := httptest.NewRequest("POST", tc.target, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		if _, ok := oauthForm(w, r); ok || w.Code != 400 {
			t.Fatalf("accepted ambiguous request: %#v", tc)
		}
	}
}
func TestOAuthPKCEVectors(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !oauthPKCE(v, c, "S256") || oauthPKCE(v+"a", c, "S256") {
		t.Fatal("RFC 7636 vector failed")
	}
	for _, v := range []string{strings.Repeat("x", 42), strings.Repeat("x", 129), strings.Repeat("x", 42) + "!"} {
		if oauthVerifier(v) {
			t.Fatal("invalid verifier accepted")
		}
	}
}
func TestOAuthClaimsScope(t *testing.T) {
	u := db.User{ID: ids.UserID(42), Username: "alice", Email: "alice@example.com"}
	v := oauthIdentity(u, "openid")
	if len(v) != 1 || v["sub"] != "42" {
		t.Fatalf("claims leaked: %v", v)
	}
	v = oauthIdentity(u, "profile email")
	if v["name"] != "alice" || v["email"] != u.Email {
		t.Fatalf("claims missing %v", v)
	}
}

func TestOAuthRejectsMixedClientAuthentication(t *testing.T) {
	a := &App{}
	for _, tc := range []struct {
		header []string
		form   url.Values
	}{{[]string{"Basic Y2xpZW50OnNlY3JldA=="}, url.Values{"client_id": {"client"}}}, {[]string{"Bearer token"}, url.Values{}}, {[]string{"Basic YTpi", "Basic YTpi"}, url.Values{}}} {
		r := httptest.NewRequest("POST", "/oauth2/token", nil)
		r.Header["Authorization"] = tc.header
		if _, e := a.oauthAuthenticate(r.Context(), nil, r, tc.form); e == nil {
			t.Fatal("accepted ambiguous authentication")
		}
	}
}
