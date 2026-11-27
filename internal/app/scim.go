package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
)

var errSCIMFenced = errors.New("SCIM worker superseded")

type scimJob struct {
	Kind       string         `json:"kind"`
	ExternalID string         `json:"externalId"`
	Desired    map[string]any `json:"desired,omitempty"`
	Members    []string       `json:"members,omitempty"`
	Delete     bool           `json:"delete,omitempty"`
}

func (a *App) scimSeal(id ids.ClientID, secret string) (string, error) {
	c, err := a.mfaCipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, c.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(c.Seal(nonce, nonce, []byte(secret), []byte(fmt.Sprintf("guard:scim:%d", id)))), nil
}
func (a *App) scimOpen(id ids.ClientID, sealed string) (string, error) {
	c, err := a.mfaCipher()
	if err != nil {
		return "", err
	}
	b, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(b) < c.NonceSize()+c.Overhead() {
		return "", scimProblem("cannot decrypt provisioning secret")
	}
	out, err := c.Open(nil, b[:c.NonceSize()], b[c.NonceSize():], []byte(fmt.Sprintf("guard:scim:%d", id)))
	if err != nil {
		return "", scimProblem("cannot decrypt provisioning secret")
	}
	return string(out), nil
}
func (a *App) saveSCIM(ctx context.Context, id ids.ClientID, endpoint, secret string, enabled bool) error {
	return a.saveSCIMAs(ctx, id, endpoint, secret, enabled, 0, nil)
}
func (a *App) saveSCIMAs(ctx context.Context, id ids.ClientID, endpoint, secret string, enabled bool, actor ids.UserID, groupPatterns *string) error {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if err := validateSCIMURL(endpoint); err != nil {
		return adminInvalid(err.Error())
	}
	if len(secret) > 4096 || strings.IndexFunc(secret, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return adminInvalid("Enter a bearer secret without spaces or control characters (maximum 4096 bytes).")
	}
	return transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, err := adminClient(ctx, q, id, true)
		if err != nil {
			return err
		}
		if c.ClientType != "Oidc" {
			return adminInvalid("SCIM requires an OpenID Connect client.")
		}
		old, err := q.GetSCIMConfig(ctx, id)
		if err != nil && !notFound(err) {
			return err
		}
		patterns := old.GroupPatterns
		if notFound(err) {
			patterns = "*"
		}
		if groupPatterns != nil {
			patterns, err = normalizeSCIMGroupPatterns(*groupPatterns)
			if err != nil {
				return err
			}
		}
		sealed := old.Secret
		if secret != "" {
			sealed, err = a.scimSeal(id, secret)
			if err != nil {
				return err
			}
		}
		if sealed == "" {
			return adminInvalid("A SCIM bearer secret is required.")
		}
		// Never accidentally send an old service's credential to a replacement URL.
		if old.Endpoint != "" && old.Endpoint != endpoint && secret == "" {
			return adminInvalid("Enter a bearer secret when changing the SCIM endpoint.")
		}
		_, err = q.SaveSCIMConfig(ctx, db.SaveSCIMConfigParams{ClientID: id, Endpoint: endpoint, Secret: sealed, Enabled: enabled, GroupPatterns: patterns})
		if err != nil {
			return err
		}
		if actor != 0 {
			return a.audit(ctx, q, actor, "SCIMConfigurationChanged", map[string]any{"client_id": id, "enabled": enabled, "endpoint_changed": old.Endpoint != endpoint, "group_scope_changed": old.GroupPatterns != patterns})
		}
		return nil
	})
}
func (a *App) scimFence(ctx context.Context, c db.ScimConfig) error {
	n, err := a.Q.FenceSCIM(ctx, db.FenceSCIMParams{ClientID: c.ClientID, Generation: c.Generation, LeaseToken: c.LeaseToken})
	return scimAffected(n, err)
}
func scimAffected(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return errSCIMFenced
	}
	return nil
}
func (a *App) scimGroupID(c db.Client, id ids.GroupID) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("guard:scim:group:%s:%d", c.ClientID, id)))
	return "guard:group:" + hex.EncodeToString(sum[:])
}

// Build and persist a consistent desired directory before doing any HTTP.
func (a *App) scimSnapshot(ctx context.Context, cfg *db.ScimConfig) ([]scimJob, error) {
	if cfg.WorkRevision != 0 && (cfg.WorkRevision == cfg.Revision || cfg.Attempts == 0) {
		var jobs []scimJob
		if err := json.Unmarshal(cfg.Snapshot, &jobs); err != nil {
			return nil, err
		}
		return jobs, nil
	}
	tx, err := a.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := db.New(tx)
	current, err := q.GetSCIMConfig(ctx, cfg.ClientID)
	if err != nil {
		return nil, err
	}
	if current.LeaseToken != cfg.LeaseToken || current.Generation != cfg.Generation || !current.Enabled {
		return nil, errSCIMFenced
	}
	client, err := q.GetClient(ctx, cfg.ClientID)
	if err != nil {
		return nil, err
	}
	users, err := q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := q.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	members, err := q.ListGroupMembers(ctx)
	if err != nil {
		return nil, err
	}
	mappings, err := q.ListSCIMMappings(ctx, db.ListSCIMMappingsParams{ClientID: cfg.ClientID, Generation: cfg.Generation})
	if err != nil {
		return nil, err
	}
	owned := map[string]db.ScimMapping{}
	for _, m := range mappings {
		owned[m.Kind+":"+m.ExternalID] = m
	}
	active := map[ids.UserID]string{}
	emailCounts := map[string]int{}
	for _, u := range users {
		if !u.Disabled && u.DeletedAt == nil && strings.TrimSpace(u.Email) != "" {
			emailCounts[strings.ToLower(u.Email)]++
		}
	}
	jobs := []scimJob{}
	seen := map[string]bool{}
	for _, u := range users {
		ext := "guard:user:" + a.oidcSubject(client, u.ID)
		permitted := false
		if !u.Disabled && u.DeletedAt == nil && strings.TrimSpace(u.Email) != "" {
			permitted, err = a.permitted(ctx, q, cfg.ClientID, u.ID)
			if err != nil {
				return nil, err
			}
		}
		if permitted && (!validEmail(u.Email) || emailCounts[strings.ToLower(u.Email)] != 1) {
			return nil, scimProblem("provisioning requires a valid, unique email for every assigned user")
		}
		_, managed := owned["Users:"+ext]
		if !permitted && !managed {
			continue
		}
		desired := map[string]any{"schemas": []string{scimUserSchema}, "externalId": ext, "active": permitted, "displayName": u.Username}
		if permitted {
			desired["userName"] = u.Email
			desired["emails"] = []any{map[string]any{"value": u.Email, "primary": true}}
			active[u.ID] = ext
		}
		jobs = append(jobs, scimJob{Kind: "Users", ExternalID: ext, Desired: desired})
		seen["Users:"+ext] = true
	}
	// Hard deletion is supported too: retain ownership and deactivate without
	// requiring the local user row or its old profile to remain present.
	for _, m := range mappings {
		if m.Kind == "Users" && !seen["Users:"+m.ExternalID] {
			jobs = append(jobs, scimJob{Kind: "Users", ExternalID: m.ExternalID, Desired: map[string]any{"schemas": []string{scimUserSchema}, "externalId": m.ExternalID, "active": false}})
		}
	}
	matchesGroup, err := scimGroupFilter(current.GroupPatterns)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.DeletedAt != nil || !matchesGroup(g.Name) {
			continue
		}
		ext := a.scimGroupID(client, g.ID)
		memberIDs := []string{}
		for _, m := range members {
			if m.GroupID == g.ID && active[m.UserID] != "" {
				memberIDs = append(memberIDs, active[m.UserID])
			}
		}
		jobs = append(jobs, scimJob{Kind: "Groups", ExternalID: ext, Desired: map[string]any{"schemas": []string{scimGroupSchema}, "externalId": ext, "displayName": g.Name}, Members: memberIDs})
		seen["Groups:"+ext] = true
	}
	for _, m := range mappings {
		if m.Kind == "Groups" && !seen["Groups:"+m.ExternalID] {
			jobs = append(jobs, scimJob{Kind: "Groups", ExternalID: m.ExternalID, Delete: true})
		}
	}
	snapshot, err := json.Marshal(jobs)
	if err != nil {
		return nil, err
	}
	n, err := q.SetSCIMSnapshot(ctx, db.SetSCIMSnapshotParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, Snapshot: snapshot, WorkRevision: current.Revision})
	if err = scimAffected(n, err); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	cfg.Revision = current.Revision
	cfg.WorkRevision = current.Revision
	cfg.Snapshot = snapshot
	cfg.Cursor = 0
	return jobs, nil
}

func (a *App) scimRun(ctx context.Context, cfg *db.ScimConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	jobs, err := a.scimSnapshot(ctx, cfg)
	if err != nil {
		return err
	}
	secret, err := a.scimOpen(cfg.ClientID, cfg.Secret)
	if err != nil {
		return err
	}
	remote := scimRemote{base: cfg.Endpoint, secret: secret, http: a.HTTP, before: func(ctx context.Context) error { return a.scimFence(ctx, *cfg) }}
	if err = remote.discover(ctx); err != nil {
		return err
	}
	mappings, err := a.Q.ListSCIMMappings(ctx, db.ListSCIMMappingsParams{ClientID: cfg.ClientID, Generation: cfg.Generation})
	if err != nil {
		return err
	}
	owned := map[string]string{}
	for _, m := range mappings {
		owned[m.Kind+":"+m.ExternalID] = m.RemoteID
	}
	end := min(int(cfg.Cursor)+25, len(jobs))
	for i := int(cfg.Cursor); i < end; i++ {
		job := jobs[i]
		key := job.Kind + ":" + job.ExternalID
		remoteID := owned[key]
		if job.Kind == "Groups" && !job.Delete {
			values := []any{}
			for _, member := range job.Members {
				id := owned["Users:"+member]
				if id == "" {
					return scimProblem("group synchronization waiting for managed users")
				}
				values = append(values, map[string]any{"value": id})
			}
			job.Desired["members"] = values
		}
		// Persist intent before any possible create. A later directory edit
		// must still discover and deactivate/delete an ambiguously created resource.
		if !job.Delete && remoteID == "" && !(job.Kind == "Users" && job.Desired["active"] == false) {
			n, e := a.Q.EnsureSCIMIntent(ctx, db.EnsureSCIMIntentParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, Kind: job.Kind, ExternalID: job.ExternalID})
			if e = scimAffected(n, e); e != nil {
				return e
			}
		}
		if job.Delete {
			if remoteID == "" {
				remoteID, err = remote.lookup(ctx, "Groups", job.ExternalID)
			}
			if err == nil && remoteID != "" {
				err = remote.deleteGroup(ctx, remoteID, job.ExternalID)
			}
		} else if job.Kind == "Users" && job.Desired["active"] == false && remoteID == "" {
			// A deactivation never creates an inactive remote account.
			remoteID, err = remote.lookup(ctx, "Users", job.ExternalID)
			if err == nil && remoteID != "" {
				remoteID, err = remote.reconcile(ctx, job.Kind, remoteID, job.Desired)
			}
		} else {
			remoteID, err = remote.reconcile(ctx, job.Kind, remoteID, job.Desired)
		}
		if err != nil {
			return err
		}
		err = transaction(ctx, a.Pool, func(q *db.Queries) error {
			if job.Delete {
				n, e := q.RemoveSCIMMapping(ctx, db.RemoveSCIMMappingParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, Kind: job.Kind, ExternalID: job.ExternalID})
				if e = scimAffected(n, e); e != nil {
					return e
				}
			} else if !job.Delete && remoteID != "" {
				n, e := q.PutSCIMMapping(ctx, db.PutSCIMMappingParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, Kind: job.Kind, ExternalID: job.ExternalID, RemoteID: remoteID})
				if e = scimAffected(n, e); e != nil {
					return e
				}
			}
			n, e := q.AdvanceSCIM(ctx, db.AdvanceSCIMParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, Cursor: int32(i + 1)})
			return scimAffected(n, e)
		})
		if err != nil {
			return err
		}
		if job.Delete {
			delete(owned, key)
		} else if remoteID != "" {
			owned[key] = remoteID
		}
	}
	if end == len(jobs) {
		n, e := a.Q.CompleteSCIM(ctx, db.CompleteSCIMParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken})
		return scimAffected(n, e)
	}
	n, e := a.Q.ReleaseSCIM(ctx, db.ReleaseSCIMParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken})
	return scimAffected(n, e)
}
func (a *App) syncSCIMOne(ctx context.Context) (bool, error) {
	cfg, err := a.Q.ClaimSCIM(ctx, security.Token())
	if notFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = a.scimRun(ctx, &cfg)
	if err == nil || errors.Is(err, errSCIMFenced) {
		return true, nil
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	message := "SCIM synchronization failed; retry pending"
	var protocol *scimError
	if errors.As(err, &protocol) {
		message = protocol.Error()
	}
	delay := logoutRetryDelay(cfg.Attempts, "", time.Now())
	if protocol != nil {
		delay = logoutRetryDelay(cfg.Attempts, protocol.retryAfter, time.Now())
	}
	failedRevision := cfg.WorkRevision
	if failedRevision == 0 {
		failedRevision = cfg.Revision
	}
	n, e := a.Q.FailSCIM(ctx, db.FailSCIMParams{ClientID: cfg.ClientID, Generation: cfg.Generation, LeaseToken: cfg.LeaseToken, LastError: message, Blocked: scimPermanent(err), Revision: failedRevision, NextAttemptAt: time.Now().Add(delay)})
	if e = scimAffected(n, e); errors.Is(e, errSCIMFenced) {
		return true, nil
	}
	return true, e
}
func (a *App) scimWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.syncSCIMOne(ctx); err != nil && ctx.Err() == nil {
				slog.Error("SCIM worker failed", "error", err)
			}
		}
	}
}
