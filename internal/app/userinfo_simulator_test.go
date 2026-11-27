package app

import (
	"context"
	"encoding/json"
	"html"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/le0developer/guard/internal/db"
)

func TestHomeUserInfoSimulatorMatchesLiveUserInfo(t *testing.T) {
	f := newOAuthFixture(t)
	status, tokens := f.post("/oauth2/token", oauthCodeFields(f.code(t)))
	if status != 200 {
		t.Fatalf("mint: %d %v", status, tokens)
	}
	request := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	live := httptest.NewRecorder()
	f.h.ServeHTTP(live, request)
	var expected map[string]any
	if err := json.Unmarshal(live.Body.Bytes(), &expected); err != nil || live.Code != 200 {
		t.Fatalf("userinfo: %d %v", live.Code, err)
	}
	for _, scope := range []string{"openid profile email", "openid"} {
		query := url.Values{"preview_client": {f.client.ClientID}, "preview_scope": {scope}}
		request = httptest.NewRequest("GET", "/?"+query.Encode(), nil)
		request = request.WithContext(context.WithValue(request.Context(), identityKey{}, f.who))
		response := httptest.NewRecorder()
		f.a.home(response, request)
		if response.Code != 200 {
			t.Fatalf("home: %d %s", response.Code, response.Body.String())
		}
		match := regexp.MustCompile(`(?s)id="userinfo-json"[^>]*>(.*?)</textarea>`).FindStringSubmatch(response.Body.String())
		if len(match) != 2 {
			t.Fatal("dashboard missing UserInfo simulator output")
		}
		var actual map[string]any
		if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &actual); err != nil {
			t.Fatal(err)
		}
		if scope == "openid" {
			expected = map[string]any{"sub": expected["sub"]}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("preview differs from live UserInfo: %v != %v", actual, expected)
		}
		if strings.Contains(response.Body.String(), f.client.ClientSecret+`"`) {
			t.Fatal("client secret leaked")
		}
	}
}

func TestHomeUserInfoSimulatorFiltersClientsAndScopes(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := context.Background()
	group, err := f.a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Restricted"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Q.CreateClientAccessRule(ctx, db.CreateClientAccessRuleParams{ClientID: f.client.ID, GroupID: group.ID, AccessControl: "Allow"}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"preview_client=client", "preview_client=unknown", "preview_client=client&preview_scope=openid+invalid"} {
		r := httptest.NewRequest("GET", "/?"+query, nil)
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
		w := httptest.NewRecorder()
		f.a.home(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), `id="userinfo-json"`) {
			t.Fatalf("unauthorized client preview: %d %s", w.Code, w.Body.String())
		}
	}
	if _, err = f.a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: group.ID, UserID: f.who.User.ID}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"openid invalid", "profile"} {
		r := httptest.NewRequest("GET", "/?"+url.Values{"preview_client": {f.client.ClientID}, "preview_scope": {scope}}.Encode(), nil)
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, f.who))
		w := httptest.NewRecorder()
		f.a.home(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), `id="userinfo-json"`) {
			t.Fatalf("invalid scope preview: %d %s", w.Code, w.Body.String())
		}
	}
}
