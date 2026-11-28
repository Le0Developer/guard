package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/le0developer/guard/internal/db"
)

func TestAdminAuditRuleChanges(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "auditor", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Engineering"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Payroll", Slug: "payroll", ClientID: "public-payroll", ClientSecret: "never-log-this-secret", ClientType: "Oidc", SessionLifetimeS: 3600})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	path := fmt.Sprintf("/admin/clients/%d/rules", c.ID)
	field := fmt.Sprintf("access_rules.%d", g.ID)
	post := func(path string, form url.Values, status int) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: actor}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		logs, err := a.Q.AdminAuditPage(ctx, 1<<63-1)
		if err != nil || len(logs) == 0 {
			t.Fatalf("logs: %v", err)
		}
		raw := string(logs[0].Data)
		if strings.Contains(raw, c.ClientSecret) {
			t.Fatal("credential leaked")
		}
		var data map[string]any
		if err := json.Unmarshal(logs[0].Data, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	form := url.Values{"group_id": {fmt.Sprint(g.ID)}, "priority": {"5"}, "access_control": {"allow"}}
	data := post(path, form, 303)
	target, ok := data["target"].(map[string]any)
	if !ok || target["name"] != "Payroll" || target["type"] != "client" {
		t.Fatalf("missing named target: %#v", data)
	}
	changes, ok := data["changes"].(map[string]any)
	if !ok {
		t.Fatalf("missing changes: %#v", data)
	}
	change := changes[field].(map[string]any)
	if change["before"] != nil {
		t.Fatalf("created rule has prior state: %#v", change)
	}
	after := change["after"].(map[string]any)
	if after["group_name"] != "Engineering" || after["priority"] != float64(5) || after["access_control"] != "Allow" {
		t.Fatalf("wrong rule: %#v", after)
	}
	form.Set("priority", "9")
	form.Set("access_control", "deny")
	data = post(path, form, 303)
	change = data["changes"].(map[string]any)[field].(map[string]any)
	before := change["before"].(map[string]any)
	after = change["after"].(map[string]any)
	if before["priority"] != float64(5) || after["priority"] != float64(9) || before["access_control"] != "Allow" || after["access_control"] != "Deny" {
		t.Fatalf("wrong diff: %#v", change)
	}
	data = post(path, form, 303)
	if data["outcome"] != "unchanged" || len(data["changes"].(map[string]any)) != 0 {
		t.Fatalf("no-op invented changes: %#v", data)
	}
	form.Set("priority", "invalid")
	data = post(path, form, 422)
	if data["outcome"] != "failed" || data["changes"] != nil {
		t.Fatalf("failure claimed changes: %#v", data)
	}
	data = post(fmt.Sprintf("%s/%d/remove", path, g.ID), nil, 303)
	change = data["changes"].(map[string]any)[field].(map[string]any)
	if change["before"] == nil || change["after"] != nil {
		t.Fatalf("missing removed rule: %#v", change)
	}
	// Persisted context survives later renames.
	_, err = a.Q.UpdateGroup(ctx, db.UpdateGroupParams{ID: g.ID, Name: "Renamed"})
	if err != nil {
		t.Fatal(err)
	}
	if change["before"].(map[string]any)["group_name"] != "Engineering" {
		t.Fatal("lost historical name")
	}
}

func TestAdminAuditSCIMChanges(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "scim-admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Directory", Slug: "directory", ClientID: "directory", ClientType: "Oidc", ClientSecret: "oidc-secret", SessionLifetimeS: 3600})
	if err != nil {
		t.Fatal(err)
	}
	first, second := "scim-first-secret", "scim-second-secret"
	if err = a.saveSCIMAs(ctx, c.ID, "https://directory.example/scim", first, true, &actor.ID, nil); err != nil {
		t.Fatal(err)
	}
	scope := "Engineering*"
	if err = a.saveSCIMAs(ctx, c.ID, "https://directory.example/scim/v2", second, false, &actor.ID, &scope); err != nil {
		t.Fatal(err)
	}
	logs, err := a.Q.AdminAuditPage(ctx, 1<<63-1)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err = json.Unmarshal(logs[0].Data, &data); err != nil {
		t.Fatal(err)
	}
	changes, ok := data["changes"].(map[string]any)
	if !ok {
		t.Fatalf("SCIM lacks changes: %#v", data)
	}
	if changes["endpoint"].(map[string]any)["before"] != "https://directory.example/scim" || changes["endpoint"].(map[string]any)["after"] != "https://directory.example/scim/v2" {
		t.Fatalf("bad endpoint diff: %#v", changes)
	}
	if changes["enabled"].(map[string]any)["after"] != false || changes["group_patterns"].(map[string]any)["after"] != "Engineering*" {
		t.Fatalf("bad SCIM settings: %#v", changes)
	}
	if data["target"].(map[string]any)["name"] != "Directory" {
		t.Fatal("missing client name")
	}
	if !strings.Contains(string(logs[0].Data), "scim_secret_changed") {
		t.Fatal("secret replacement missing")
	}
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, log := range logs {
		for _, secret := range []string{first, second, c.ClientSecret, cfg.Secret} {
			if strings.Contains(string(log.Data), secret) {
				t.Fatal("credential leaked")
			}
		}
	}
}

func TestAdminAuditJournalSummary(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "journal-admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.audit(ctx, a.Q, actor.ID, "AdminAction", map[string]any{"summary": "Access rule saved", "target": map[string]any{"name": "Payroll"}}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	r := httptest.NewRequest("GET", "/admin/audit", nil).WithContext(context.WithValue(ctx, identityKey{}, &identity{User: actor}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<td>Access rule saved · Payroll</td>") {
		t.Fatalf("missing readable summary: %d %s", w.Code, w.Body.String())
	}
}

// Audit failure must roll back the mutation, rather than leave an unlogged change.
func TestAdminAuditFailureRollsBackMutation(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "rollback-admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Original"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Pool.Exec(ctx, `CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; CREATE TRIGGER reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/admin/groups/%d", g.ID), nil)
	r.SetPathValue("id", fmt.Sprint(g.ID))
	r.PostForm = url.Values{"name": {"Unlogged"}}
	err = a.adminWrite(httptest.NewRecorder(), r, &identity{User: actor}, "groups")
	if err == nil {
		t.Fatal("audit failure accepted")
	}
	saved, err := a.Q.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Name != "Original" {
		t.Fatal("mutation committed without audit")
	}
	logs, err := a.Q.ListAuditLogs(ctx)
	if err != nil || len(logs) != 0 {
		t.Fatalf("unexpected logs: %v %v", logs, err)
	}
}

func TestAdminAuditLifecycle(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "lifecycle-admin", Role: "Admin", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	post := func(path string, form url.Values) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(ctx, identityKey{}, &identity{User: actor}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 303 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		logs, err := a.Q.AdminAuditPage(ctx, 1<<63-1)
		if err != nil || len(logs) == 0 {
			t.Fatalf("logs: %v", err)
		}
		var data map[string]any
		if err = json.Unmarshal(logs[0].Data, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	change := func(data map[string]any, field string) map[string]any {
		t.Helper()
		v, ok := data["changes"].(map[string]any)[field].(map[string]any)
		if !ok {
			t.Fatalf("missing %s: %#v", field, data)
		}
		return v
	}
	data := post("/admin/users", url.Values{"username": {"alice"}, "email": {"alice@example.org"}, "role": {"User"}, "password": {"first-password"}})
	if data["outcome"] != "created" || change(data, "username")["before"] != nil || change(data, "username")["after"] != "alice" {
		t.Fatalf("user create: %#v", data)
	}
	u, err := a.Q.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	userPath := fmt.Sprintf("/admin/users/%d", u.ID)
	data = post(userPath, url.Values{"username": {"alice"}, "email": {"new@example.org"}})
	if change(data, "email")["before"] != "alice@example.org" || change(data, "email")["after"] != "new@example.org" {
		t.Fatalf("user update: %#v", data)
	}
	data = post(userPath+"/role", url.Values{"role": {"Admin"}, "current_role": {"User"}})
	if change(data, "role")["before"] != "User" || change(data, "role")["after"] != "Admin" {
		t.Fatalf("role change: %#v", data)
	}
	session, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: "session-hash-never-log", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	data = post(userPath+"/sessions/"+fmt.Sprint(session.ID)+"/delete", nil)
	if change(data, fmt.Sprintf("sessions.%d", session.ID))["after"] != nil {
		t.Fatalf("session removal: %#v", data)
	}
	data = post(userPath+"/password", url.Values{"password": {"replacement-password"}, "confirm_password": {"replacement-password"}})
	operations := data["operations"].([]any)
	found := false
	for _, op := range operations {
		if op == "password_changed" {
			found = true
		}
	}
	if !found {
		t.Fatal("password replacement not recorded")
	}
	data = post("/admin/groups", url.Values{"name": {"Engineering"}})
	if data["outcome"] != "created" {
		t.Fatalf("group create: %#v", data)
	}
	groups, err := a.Q.ListGroups(ctx)
	if err != nil || len(groups) != 1 {
		t.Fatal(err)
	}
	g := groups[0]
	groupPath := fmt.Sprintf("/admin/groups/%d", g.ID)
	data = post(groupPath+"/members", url.Values{"user_id": {fmt.Sprint(u.ID)}})
	field := fmt.Sprintf("members.%d", u.ID)
	if change(data, field)["before"] != nil || change(data, field)["after"].(map[string]any)["username"] != "alice" {
		t.Fatalf("member add: %#v", data)
	}
	data = post(groupPath+"/members/"+fmt.Sprint(u.ID)+"/remove", nil)
	if change(data, field)["before"] == nil || change(data, field)["after"] != nil {
		t.Fatalf("member remove: %#v", data)
	}
	data = post("/admin/clients", url.Values{"name": {"Payroll"}, "client_type": {"Oidc"}, "session_lifetime_s": {"3600"}})
	if data["outcome"] != "created" {
		t.Fatalf("client create: %#v", data)
	}
	clients, err := a.Q.ListClients(ctx)
	if err != nil || len(clients) != 1 {
		t.Fatal(err)
	}
	c := clients[0]
	clientPath := fmt.Sprintf("/admin/clients/%d", c.ID)
	data = post(clientPath, url.Values{"name": {"Payroll revised"}, "client_type": {"Oidc"}, "session_lifetime_s": {"7200"}})
	if change(data, "name")["before"] != "Payroll" || change(data, "session_lifetime_s")["after"] != float64(7200) {
		t.Fatalf("client update: %#v", data)
	}
	data = post(clientPath+"/rotate-secret", url.Values{"confirm": {"rotate"}})
	if len(data["operations"].([]any)) != 1 || data["operations"].([]any)[0] != "client_secret_changed" {
		t.Fatalf("secret rotation: %#v", data)
	}
	data = post(clientPath+"/redirects", url.Values{"redirect_uri": {"https://payroll.example/callback"}})
	redirects, err := a.Q.ClientRedirectsByClientId(ctx, c.ID)
	if err != nil || len(redirects) != 1 {
		t.Fatal(err)
	}
	redirect := redirects[0]
	redirectField := fmt.Sprintf("redirects.%d", redirect.ID)
	if change(data, redirectField)["after"] != "https://payroll.example/callback" {
		t.Fatalf("redirect add: %#v", data)
	}
	data = post(fmt.Sprintf("%s/redirects/%d", clientPath, redirect.ID), url.Values{"redirect_uri": {"https://payroll.example/new"}})
	if change(data, redirectField)["before"] != "https://payroll.example/callback" || change(data, redirectField)["after"] != "https://payroll.example/new" {
		t.Fatalf("redirect update: %#v", data)
	}
	data = post(fmt.Sprintf("%s/redirects/%d/remove", clientPath, redirect.ID), nil)
	if change(data, redirectField)["after"] != nil {
		t.Fatalf("redirect remove: %#v", data)
	}
	for _, path := range []string{userPath, groupPath, clientPath} {
		data = post(path+"/delete", nil)
		if data["outcome"] != "deleted" || change(data, "deleted")["before"] != false || change(data, "deleted")["after"] != true {
			t.Fatalf("delete %s: %#v", path, data)
		}
	}
	operations = data["operations"].([]any)
	for _, want := range []string{"authorization_codes_invalidated", "forward_auth_requests_invalidated", "forward_auth_sessions_revoked"} {
		found := false
		for _, op := range operations {
			if op == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("client deletion omitted %s: %#v", want, data)
		}
	}
	logs, err := a.Q.ListAuditLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := a.Q.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, log := range logs {
		for _, secret := range []string{"first-password", "replacement-password", u.Password, c.ClientSecret, rotated.ClientSecret, "session-hash-never-log"} {
			if secret != "" && strings.Contains(string(log.Data), secret) {
				t.Fatal("audit contains credential")
			}
		}
	}
}

func TestAdminAuditLegacyLabels(t *testing.T) {
	for _, raw := range []string{`{"action":"POST /admin/clients/{id}/rules","status":303,"target_id":4}`, `invalid`, `{"summary":17}`} {
		if label := adminAuditLabel("AdminAction", []byte(raw)); label != "AdminAction" {
			t.Fatalf("legacy label: %q", label)
		}
	}
	if label := adminAuditLabel("SCIMSyncRequested", []byte(`{"summary":"SCIM synchronization requested","target":{"name":"<script>"}}`)); label != "SCIM synchronization requested · <script>" {
		t.Fatal(label)
	}
}

func TestAdminAuditDoesNotAttributeRelatedRenames(t *testing.T) {
	for _, tc := range []struct{ field, label string }{
		{"members.1", "username"}, {"groups.1", "group_name"}, {"access_rules.1", "group_name"}, {"client_access_rules.1", "client_name"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			before := &adminAuditState{Fields: map[string]any{tc.field: map[string]any{"id": 1, tc.label: "Old name", "priority": 5}}}
			after := &adminAuditState{Fields: map[string]any{tc.field: map[string]any{"id": 1, tc.label: "New name", "priority": 5}}}
			changes, _ := adminAuditDiff(before, after)
			if len(changes) != 0 {
				t.Fatalf("attributed unrelated rename: %#v", changes)
			}
			after.Fields[tc.field].(map[string]any)["priority"] = 9
			changes, _ = adminAuditDiff(before, after)
			change := changes[tc.field].(map[string]any)
			if change["before"].(map[string]any)[tc.label] != "Old name" || change["after"].(map[string]any)[tc.label] != "New name" {
				t.Fatal("changed relation lost saved name context")
			}
		})
	}
}

func TestAdminAuditSCIMSystemAdministrator(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	actor, err := a.Q.BootstrapUser(ctx, db.BootstrapUserParams{Password: "unused", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Root directory", Slug: "root-directory", ClientID: "root-directory", ClientType: "Oidc", ClientSecret: "unused", SessionLifetimeS: 3600})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	form := url.Values{"endpoint": {"https://directory.example/scim"}, "secret": {"root-bearer-secret"}, "enabled": {"on"}}
	r := httptest.NewRequest("POST", scimAdminPath(c.ID), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(ctx, identityKey{}, &identity{User: actor}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	logs, err := a.Q.ListAuditLogs(ctx)
	if err != nil || len(logs) != 1 {
		t.Fatalf("system admin action missing: logs=%v err=%v", logs, err)
	}
	if logs[0].UserID != 0 || !strings.Contains(string(logs[0].Data), "Root directory") || strings.Contains(string(logs[0].Data), "root-bearer-secret") {
		t.Fatalf("unsafe or misattributed audit: %#v", logs[0])
	}
}
