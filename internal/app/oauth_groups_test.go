package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
)

func TestOAuthGroupsScope(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	if !oauthScope("openid groups") {
		t.Fatal("groups scope rejected")
	}
	metadataRequest := httptest.NewRequest("GET", "/oauth2/test/.well-known/openid-configuration", nil)
	metadataResponse := httptest.NewRecorder()
	f.h.ServeHTTP(metadataResponse, metadataRequest)
	var metadata map[string]any
	if err := json.Unmarshal(metadataResponse.Body.Bytes(), &metadata); err != nil || metadataResponse.Code != 200 {
		t.Fatal("discovery failed", err)
	}
	for _, field := range []string{"scopes_supported", "claims_supported"} {
		found := false
		for _, v := range metadata[field].([]any) {
			if v == "groups" {
				found = true
			}
		}
		if !found {
			t.Errorf("discovery omits groups from %s", field)
		}
	}
	groups := []db.Group{}
	for _, name := range []string{"staff", "engineering", "deleted", "unrelated"} {
		p := db.CreateGroupParams{Name: name}
		if name == "deleted" {
			p.DeletedAt = ptr(time.Now())
		}
		g, err := f.a.Q.CreateGroup(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g)
		if name != "unrelated" {
			if _, err = f.a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: f.who.User.ID}); err != nil {
				t.Fatal(err)
			}
		}
	}
	decode := func(raw string) map[string]any {
		t.Helper()
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatal("invalid ID token")
		}
		b, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err = json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	check := func(v map[string]any, want any) {
		t.Helper()
		if !reflect.DeepEqual(v["groups"], want) {
			t.Fatalf("groups: got %#v want %#v", v["groups"], want)
		}
		if _, ok := v["role"]; ok {
			t.Fatal("administrator permission leaked as role")
		}
	}
	info := func(token string) map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	status, tokens := f.post("/oauth2/token", oauthCodeFields(f.codeScope(t, "openid groups")))
	if status != 200 {
		t.Fatalf("token: %d %v", status, tokens)
	}
	want := []any{"engineering", "staff"}
	check(decode(tokens["id_token"].(string)), want)
	check(info(tokens["access_token"].(string)), want)
	if err := f.a.Q.DeleteGroupMember(ctx, db.DeleteGroupMemberParams{GroupID: groups[0].ID, UserID: f.who.User.ID}); err != nil {
		t.Fatal(err)
	}
	check(info(tokens["access_token"].(string)), []any{"engineering"})
	status, refreshed := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	if status != 200 {
		t.Fatalf("refresh: %d %v", status, refreshed)
	}
	check(decode(refreshed["id_token"].(string)), []any{"engineering"})
	status, reduced := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed["refresh_token"].(string)}, "scope": {"openid"}})
	if status != 200 {
		t.Fatalf("scope reduction: %d %v", status, reduced)
	}
	status, escalated := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {reduced["refresh_token"].(string)}, "scope": {"openid groups"}})
	if status != 400 || escalated["error"] != "invalid_scope" {
		t.Fatalf("refresh added ungranted groups scope: %d %v", status, escalated)
	}
	check(decode(reduced["id_token"].(string)), nil)
	check(info(reduced["access_token"].(string)), nil)
	if err := f.a.Q.DeleteGroupMember(ctx, db.DeleteGroupMemberParams{GroupID: groups[1].ID, UserID: f.who.User.ID}); err != nil {
		t.Fatal(err)
	}
	status, empty := f.post("/oauth2/token", oauthCodeFields(f.codeScope(t, "openid groups")))
	if status != 200 {
		t.Fatalf("empty groups: %d %v", status, empty)
	}
	check(decode(empty["id_token"].(string)), []any{})
	check(info(empty["access_token"].(string)), []any{})
}
