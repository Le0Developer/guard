package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
)

type scimFixture struct {
	mu         sync.Mutex
	resources  map[string]map[string]any
	next       int
	fail       int
	failCreate string
}

func newSCIMFixture(t *testing.T) (*scimFixture, *httptest.Server) {
	t.Helper()
	f := &scimFixture{resources: map[string]map[string]any{}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			w.WriteHeader(401)
			return
		}
		if f.fail != 0 {
			w.WriteHeader(f.fail)
			return
		}
		resource := strings.TrimPrefix(r.URL.Path, "/scim/")
		if resource == "ServiceProviderConfig" {
			fmt.Fprint(w, `{"patch":{"supported":true}}`)
			return
		}
		switch r.Method {
		case "GET":
			if !strings.Contains(resource, "/") {
				filter := r.URL.Query().Get("filter")
				rows := []any{}
				for k, v := range f.resources {
					if strings.HasPrefix(k, resource+"/") && filter == fmt.Sprintf("externalId eq %q", v["externalId"]) {
						rows = append(rows, v)
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"totalResults": len(rows), "Resources": rows})
				return
			}
			v, ok := f.resources[resource]
			if !ok {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(v)
		case "POST":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			f.next++
			id := fmt.Sprint(f.next)
			body["id"] = id
			f.resources[resource+"/"+id] = body
			if f.failCreate == resource {
				f.failCreate = ""
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(body)
		case "PATCH":
			v, ok := f.resources[resource]
			if !ok {
				w.WriteHeader(404)
				return
			}
			var body struct {
				Operations []struct {
					Value map[string]any `json:"value"`
				} `json:"Operations"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			for _, op := range body.Operations {
				for k, val := range op.Value {
					v[k] = val
				}
			}
			w.WriteHeader(204)
		case "DELETE":
			delete(f.resources, resource)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	t.Cleanup(s.Close)
	return f, s
}
func setupSCIM(t *testing.T) (*App, db.Client, db.User, *scimFixture) {
	t.Helper()
	a := testApp(t)
	ctx := context.Background()
	f, s := newSCIMFixture(t)
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "SCIM", Slug: "scim", ClientType: "Oidc", ClientID: "scim-client", ClientSecret: "client-secret", SessionLifetimeS: 3600})
	if err != nil {
		t.Fatal(err)
	}
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "alice", Email: "alice@example.org", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	// Bootstrap system account has no email; keep it outside provisioning scope.
	if _, err = a.Pool.Exec(ctx, `UPDATE users SET disabled=true WHERE username='system'`); err != nil {
		t.Fatal(err)
	}
	if err = a.saveSCIM(ctx, c.ID, s.URL+"/scim", "test-secret", true); err != nil {
		t.Fatal(err)
	}
	return a, c, u, f
}
func drainSCIM(t *testing.T, a *App) {
	t.Helper()
	for i := 0; i < 20; i++ {
		worked, err := a.syncSCIMOne(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			return
		}
	}
	t.Fatal("reconciliation did not drain")
}
func TestSCIMSyncLifecycle(t *testing.T) {
	a, c, u, f := setupSCIM(t)
	ctx := context.Background()
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Engineering"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	if len(f.resources) != 2 {
		t.Fatalf("resources %#v", f.resources)
	}
	var uid, gid string
	for k, v := range f.resources {
		if strings.HasPrefix(k, "Users/") {
			uid = k
			if v["userName"] != "alice@example.org" {
				t.Fatal(v)
			}
		} else {
			gid = k
			if len(v["members"].([]any)) != 1 {
				t.Fatal(v)
			}
		}
	}
	f.mu.Unlock()
	if _, err = a.Pool.Exec(ctx, `UPDATE users SET username='renamed',disabled=true WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	if f.resources[uid]["active"] != false || f.resources[uid]["displayName"] != "renamed" {
		t.Fatal(f.resources[uid])
	}
	if len(f.resources[gid]["members"].([]any)) != 0 {
		t.Fatal(f.resources[gid])
	}
	f.mu.Unlock()
	if _, err = a.Pool.Exec(ctx, `UPDATE users SET disabled=false WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	if f.resources[uid]["active"] != true || len(f.resources) != 2 {
		t.Fatal(f.resources)
	}
	f.mu.Unlock()
	if _, err = a.Pool.Exec(ctx, `UPDATE groups SET deleted_at=now() WHERE id=$1`, g.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	if len(f.resources) != 1 {
		t.Fatal(f.resources)
	}
	f.mu.Unlock()
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || cfg.LastSuccessAt == nil || cfg.LastError != "" {
		t.Fatalf("status %#v %v", cfg, err)
	}
	if strings.Contains(cfg.Secret, "test-secret") {
		t.Fatal("plaintext stored")
	}
}
func TestSCIMSyncFailureAndRestart(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	f.fail = 503
	if worked, err := a.syncSCIMOne(ctx); err != nil || !worked {
		t.Fatalf("%v %v", worked, err)
	}
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || cfg.Attempts != 1 || cfg.LastError == "" || cfg.LastSuccessAt != nil {
		t.Fatalf("retry %#v %v", cfg, err)
	}
	f.mu.Lock()
	f.fail = 0
	f.mu.Unlock()
	if _, err = a.Pool.Exec(ctx, `UPDATE scim_configs SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(a.Pool, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, restarted)
	cfg, _ = a.Q.GetSCIMConfig(ctx, c.ID)
	if cfg.LastSuccessAt == nil || cfg.LastError != "" {
		t.Fatal(cfg)
	}
}
func TestSCIMSyncDuplicateEmailBlocksWithoutMerging(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	if _, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "other", Email: "ALICE@example.org", Role: "User", WebauthnUserID: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	if !cfg.Blocked || !strings.Contains(cfg.LastError, "email") {
		t.Fatal(cfg)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 0 {
		t.Fatal("created ambiguous users")
	}
}
func TestSCIMSecretBinding(t *testing.T) {
	a, c, _, _ := setupSCIM(t)
	cfg, err := a.Q.GetSCIMConfig(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.scimOpen(ids.ClientID(98765), cfg.Secret); err == nil {
		t.Fatal("secret not bound to client")
	}
}
func TestSCIMSyncStaleLeaseCannotCommit(t *testing.T) {
	a, c, _, _ := setupSCIM(t)
	ctx := context.Background()
	cfg, err := a.Q.ClaimSCIM(ctx, "old-worker")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Pool.Exec(ctx, `UPDATE scim_configs SET lease_until=now()-interval '1 second' WHERE client_id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	next, err := a.Q.ClaimSCIM(ctx, "new-worker")
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation != cfg.Generation {
		t.Fatal("unexpected generation")
	}
	if err = a.scimFence(ctx, cfg); err == nil {
		t.Fatal("stale worker not fenced")
	}
	if err = a.scimFence(ctx, next); err != nil {
		t.Fatal(err)
	}
}

func TestSCIMSyncScopeLossAndRestore(t *testing.T) {
	a, c, u, f := setupSCIM(t)
	ctx := context.Background()
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Assigned"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Q.CreateClientAccessRule(ctx, db.CreateClientAccessRuleParams{ClientID: c.ID, GroupID: g.ID, Priority: 0, AccessControl: "Allow"}); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	if _, err = a.Pool.Exec(ctx, `DELETE FROM group_members WHERE user_id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	for k, v := range f.resources {
		if strings.HasPrefix(k, "Users/") && v["active"] != false {
			t.Fatal("out-of-scope user still active")
		}
	}
	f.mu.Unlock()
	if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 2 {
		t.Fatal("restoration duplicated resources")
	}
	for k, v := range f.resources {
		if strings.HasPrefix(k, "Users/") && v["active"] != true {
			t.Fatal("restored user inactive")
		}
	}
}
func TestSCIMSyncProgressAndConcurrentDirectoryEdit(t *testing.T) {
	a, c, u, f := setupSCIM(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if _, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: fmt.Sprintf("user%d", i), Email: fmt.Sprintf("user%d@example.org", i), Role: "User", WebauthnUserID: []byte{1}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.syncSCIMOne(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || cfg.Cursor != 25 || cfg.WorkRevision == 0 || cfg.LeaseToken != "" {
		t.Fatalf("cursor not persisted %#v %v", cfg, err)
	}
	if _, err = a.Pool.Exec(ctx, `UPDATE users SET username='new-name' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 31 {
		t.Fatalf("resources %d", len(f.resources))
	}
	found := false
	for _, v := range f.resources {
		if v["userName"] == "alice@example.org" {
			found = v["displayName"] == "new-name"
		}
	}
	if !found {
		t.Fatal("concurrent edit lost")
	}
}
func TestSCIMSyncConfigReplacementFencesOldWorker(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	old, err := a.Q.ClaimSCIM(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.saveSCIM(ctx, c.ID, "https://replacement.example.org/scim", "replacement-secret", true); err != nil {
		t.Fatal(err)
	}
	if err = a.scimRun(ctx, &old); err != errSCIMFenced {
		t.Fatalf("old worker ran: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 0 {
		t.Fatal("stale worker reached old endpoint")
	}
}
func TestSCIMSyncRemoteDriftAndMissingResources(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	drainSCIM(t, a)
	f.mu.Lock()
	for _, v := range f.resources {
		v["displayName"] = "remote-edit"
	}
	f.mu.Unlock()
	if _, err := a.Q.RequestSCIMSync(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	for _, v := range f.resources {
		if v["displayName"] != "alice" {
			t.Fatal("drift unrepaired")
		}
	}
	f.resources = map[string]map[string]any{}
	f.mu.Unlock()
	if _, err := a.Q.RequestSCIMSync(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	drainSCIM(t, a)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 1 {
		t.Fatal("missing resource unrepaired")
	}
}

func TestSCIMSyncAmbiguousCreateThenDirectoryRemoval(t *testing.T) {
	for _, kind := range []string{"Users", "Groups"} {
		t.Run(kind, func(t *testing.T) {
			a, c, u, f := setupSCIM(t)
			ctx := context.Background()
			g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Soon gone"})
			if err != nil {
				t.Fatal(err)
			}
			f.failCreate = kind
			if _, err = a.syncSCIMOne(ctx); err != nil {
				t.Fatal(err)
			}
			if kind == "Users" {
				_, err = a.Pool.Exec(ctx, `UPDATE users SET disabled=true WHERE id=$1`, u.ID)
			} else {
				_, err = a.Pool.Exec(ctx, `UPDATE groups SET deleted_at=now() WHERE id=$1`, g.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			drainSCIM(t, a)
			cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
			if cfg.LastError != "" {
				t.Fatal(cfg.LastError)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for key, v := range f.resources {
				if kind == "Users" && strings.HasPrefix(key, "Users/") && v["active"] != false {
					t.Fatal("untracked orphan user remains active")
				}
				if kind == "Groups" && strings.HasPrefix(key, "Groups/") {
					t.Fatal("untracked orphan group remains")
				}
			}
		})
	}
}
func TestSCIMSyncEditsDoNotStarveLaterJobs(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	for i := 0; i < 55; i++ {
		if _, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: fmt.Sprintf("group-%02d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := a.syncSCIMOne(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Pool.Exec(ctx, `UPDATE users SET username=username WHERE username='alice'`); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 56 {
		t.Fatalf("later jobs starved: %d resources", len(f.resources))
	}
	cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	if cfg.LastSuccessAt == nil {
		t.Fatal("never completed original snapshot")
	}
}

func TestSCIMSyncPermanentErrorAndDisable(t *testing.T) {
	a, c, _, f := setupSCIM(t)
	ctx := context.Background()
	f.fail = 401
	drainSCIM(t, a)
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || !cfg.Blocked || !strings.Contains(cfg.LastError, "401") {
		t.Fatalf("auth error status %#v %v", cfg, err)
	}
	if err = a.saveSCIM(ctx, c.ID, cfg.Endpoint, "", false); err != nil {
		t.Fatal(err)
	}
	if worked, err := a.syncSCIMOne(ctx); err != nil || worked {
		t.Fatalf("disabled provisioning ran: %v %v", worked, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 0 {
		t.Fatal("disabled provisioning delivered resources")
	}
}
func TestSCIMSyncClientConversionStopsDelivery(t *testing.T) {
	a, c, _, _ := setupSCIM(t)
	ctx := context.Background()
	if _, err := a.Pool.Exec(ctx, `UPDATE clients SET client_type='ForwardAuth' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	cfg, _ := a.Q.GetSCIMConfig(ctx, c.ID)
	if cfg.Enabled {
		t.Fatal("converted client still enabled")
	}
	if worked, err := a.syncSCIMOne(ctx); err != nil || worked {
		t.Fatalf("converted client delivered %v %v", worked, err)
	}
}

func TestSCIMSyncSkipsUsersWithoutEmail(t *testing.T) {
	a, c, u, f := setupSCIM(t)
	ctx := context.Background()
	// Bootstrap administrators and other accounts without email must not block sync.
	if _, err := a.Pool.Exec(ctx, `UPDATE users SET disabled=false WHERE username='system'`); err != nil {
		t.Fatal(err)
	}
	blank, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "no-email", Email: "", Role: "User", WebauthnUserID: []byte{3}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "Team"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []ids.UserID{u.ID, blank.ID} {
		if _, err = a.Q.CreateGroupMember(ctx, db.CreateGroupMemberParams{GroupID: g.ID, UserID: id}); err != nil {
			t.Fatal(err)
		}
	}
	drainSCIM(t, a)
	cfg, err := a.Q.GetSCIMConfig(ctx, c.ID)
	if err != nil || cfg.Blocked || cfg.LastSuccessAt == nil {
		t.Fatalf("email-less users blocked sync: %#v %v", cfg, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resources) != 2 {
		t.Fatalf("expected Alice and Team, got %#v", f.resources)
	}
	for key, v := range f.resources {
		if strings.HasPrefix(key, "Users/") && v["userName"] != "alice@example.org" {
			t.Fatal("provisioned email-less user")
		}
		if strings.HasPrefix(key, "Groups/") && len(v["members"].([]any)) != 1 {
			t.Fatal("email-less member included in group")
		}
	}
}
