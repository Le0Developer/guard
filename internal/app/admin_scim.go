package app

import (
	"fmt"
	"net/http"
	"time"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
)

type scimAdminView struct {
	Client                                db.Client
	Endpoint                              string
	GroupPatterns                         string
	Enabled, Configured, Blocked, Running bool
	LastError, Status                     string
	LastSuccess                           *time.Time
	NextAttempt                           time.Time
}

func scimAdminPath(id ids.ClientID) string { return fmt.Sprintf("/admin/clients/%d/scim", id) }
func (a *App) adminSCIM(w http.ResponseWriter, r *http.Request, _ *identity) error {
	id, err := adminID[ids.ClientID](r.PathValue("id"))
	if err != nil {
		return err
	}
	c, err := adminClient(r.Context(), a.Q, id, false)
	if err != nil {
		return err
	}
	if c.ClientType != "Oidc" {
		return adminMissing()
	}
	cfg, err := a.Q.GetSCIMConfig(r.Context(), id)
	if err != nil && !notFound(err) {
		return err
	}
	view := scimAdminView{Client: c, Endpoint: cfg.Endpoint, GroupPatterns: cfg.GroupPatterns, Enabled: cfg.Enabled, Configured: err == nil, Blocked: cfg.Blocked, LastError: cfg.LastError, LastSuccess: cfg.LastSuccessAt, NextAttempt: cfg.NextAttemptAt}
	view.Running = cfg.LeaseUntil != nil && cfg.LeaseUntil.After(time.Now())
	switch {
	case !view.Configured:
		view.Status = "Not configured"
	case !view.Enabled:
		view.Status = "Disabled"
	case view.Blocked:
		view.Status = "Needs attention"
	case view.Running:
		view.Status = "Synchronizing"
	case view.LastError != "":
		view.Status = "Retry pending"
	case view.LastSuccess == nil || cfg.WorkRevision != 0 || !cfg.NextAttemptAt.After(time.Now()):
		view.Status = "Pending"
	default:
		view.Status = "Synchronized"
	}
	a.page(w, r, "SCIM provisioning", adminSCIMTemplate, view)
	return nil
}
func (a *App) adminSCIMSave(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, err := adminID[ids.ClientID](r.PathValue("id"))
	if err != nil {
		return err
	}
	var patterns *string
	if r.Form.Has("group_patterns") {
		value := r.Form.Get("group_patterns")
		patterns = &value
	}
	if err = a.saveSCIMAs(r.Context(), id, r.Form.Get("endpoint"), r.Form.Get("secret"), r.Form.Get("enabled") == "on", &actor.User.ID, patterns); err != nil {
		return err
	}
	http.Redirect(w, r, scimAdminPath(id), http.StatusSeeOther)
	return nil
}
func (a *App) adminSCIMSync(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, err := adminID[ids.ClientID](r.PathValue("id"))
	if err != nil {
		return err
	}
	err = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		c, e := adminClient(r.Context(), q, id, true)
		if e != nil {
			return e
		}
		if c.ClientType != "Oidc" {
			return adminMissing()
		}
		n, e := q.RequestSCIMSync(r.Context(), id)
		if e != nil {
			return e
		}
		if n == 0 {
			return adminInvalid("Enable SCIM provisioning before requesting synchronization.")
		}
		return a.audit(r.Context(), q, actor.User.ID, "SCIMSyncRequested", map[string]any{"client_id": id, "summary": "SCIM synchronization requested", "outcome": "requested", "target": map[string]any{"type": "client", "id": id, "name": c.Name}, "operations": []string{"scim_sync_requested"}})
	})
	if err != nil {
		return err
	}
	http.Redirect(w, r, scimAdminPath(id), http.StatusSeeOther)
	return nil
}
