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

func TestSCIMGroupWhitelistPatterns(t *testing.T) {
	for _, tc := range []struct {
		patterns, name string
		want           bool
	}{
		{"", "Team", false}, {"*", "Team/Operations", true}, {"Team", "Team", true}, {"Team", "Team-extra", false},
		{"team-*", "team-engineering", true}, {"team-*", "Team-engineering", false}, {"*-admins", "team-admins", true},
		{"dept-*-admins", "dept-eu-admins", true}, {"dept-*-admins", "dept-eu-users", false}, {"team/*", "team/platform", true},
		{"[literal]?", "[literal]?", true}, {"[literal]?", "x", false}, {" Staff \r\n team-*\n\n", "Staff", true},
	} {
		t.Run(fmt.Sprintf("%q/%q", tc.patterns, tc.name), func(t *testing.T) {
			match, err := scimGroupFilter(tc.patterns)
			if err != nil {
				t.Fatal(err)
			}
			if got := match(tc.name); got != tc.want {
				t.Fatalf("matches=%v want=%v", got, tc.want)
			}
		})
	}
	for _, bad := range []string{"name\x00", strings.Repeat("x", 201), strings.Repeat("group\n", 101)} {
		if _, err := normalizeSCIMGroupPatterns(bad); err == nil {
			t.Fatal("accepted oversized or control-character patterns")
		}
	}
}

func TestSCIMSyncGroupWhitelistAndRemoval(t *testing.T) {
	a, c, u, f := setupSCIM(t)
	ctx := context.Background()
	for _, name := range []string{"team-dev", "team-ops", "Admins", "Private"} {
		g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GroupPatterns != "*" {
		t.Fatal("existing provisioning scope not preserved")
	}
	drainSCIM(t, a)
	whitelist := "team-*\nAdmins"
	if err = a.saveSCIMAs(ctx, c.ID, cfg.Endpoint, "", true, 0, &whitelist); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	names := map[string]bool{}
	for key, v := range f.resources {
		if strings.HasPrefix(key, "Groups/") {
			names[v["displayName"].(string)] = true
		}
	}
	f.mu.Unlock()
	if len(names) != 3 || !names["team-dev"] || !names["team-ops"] || !names["Admins"] {
		t.Fatalf("wrong whitelist population %#v", names)
	}
	whitelist = ""
	if err = a.saveSCIMAs(ctx, c.ID, cfg.Endpoint, "", true, 0, &whitelist); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	defer f.mu.Unlock()
	for key := range f.resources {
		if strings.HasPrefix(key, "Groups/") {
			t.Fatal("clearing whitelist retained managed group")
		}
	}
	if len(f.resources) != 1 {
		t.Fatal("group whitelist changed user provisioning")
	}
}

func TestAdminSCIMGroupWhitelistPersists(t *testing.T) {
	a, c, u, _ := setupSCIM(t)
	u.Role = "Admin"
	ctx := context.Background()
	cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	route := fmt.Sprintf("/admin/clients/%d/scim", c.ID)
	form := url.Values{"endpoint": {cfg.Endpoint}, "enabled": {"on"}, "group_patterns": {" team-*\r\n Admins \nteam-*\n"}}
	r := httptest.NewRequest("POST", route, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(ctx, identityKey{}, &identity{User: u}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("save %d %s", w.Code, w.Body.String())
	}
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || cfg.GroupPatterns != "team-*\nAdmins" {
		t.Fatalf("patterns not normalized/persisted %#v %v", cfg, err)
	}
	r = httptest.NewRequest("GET", route, nil)
	r = r.WithContext(context.WithValue(ctx, identityKey{}, &identity{User: u}))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="group_patterns"`) || !strings.Contains(w.Body.String(), "team-*\nAdmins") {
		t.Fatalf("patterns not rendered %d %s", w.Code, w.Body.String())
	}
	// A form opened before the upgrade has no whitelist field; preserve its scope.
	form.Del("group_patterns")
	r = httptest.NewRequest("POST", route, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(ctx, identityKey{}, &identity{User: u}))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	cfg, err = a.Q.GetSCIMConfig(ctx, c.ID)
	if w.Code != 303 || err != nil || cfg.GroupPatterns != "team-*\nAdmins" {
		t.Fatalf("older form cleared whitelist: status %d patterns %q error %v", w.Code, cfg.GroupPatterns, err)
	}

}
