package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
)

type adminError struct {
	status  int
	message string
}

func (e adminError) Error() string { return e.message }
func adminInvalid(s string) error  { return adminError{422, s} }
func adminMissing() error          { return adminError{404, "Not found."} }
func adminID[T ~int64](s string) (T, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, adminMissing()
	}
	return T(n), nil
}
func adminRequired(s, name string, max int) error {
	if strings.TrimSpace(s) == "" || len(s) > max || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return adminInvalid(fmt.Sprintf("%s is required and must contain at most %d bytes.", name, max))
	}
	return nil
}
func adminRedirectError(s string) error {
	if len(s) == 0 || len(s) > 2048 || strings.ContainsAny(s, "*#") {
		return adminInvalid("Enter an exact HTTP or HTTPS URL without wildcards or fragments (maximum 2048 bytes).")
	}
	if _, err := security.URL(s); err != nil {
		return adminInvalid("Enter an exact HTTP or HTTPS URL without credentials, spaces or fragments.")
	}
	return nil
}
func (a *App) adminResult(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	var e adminError
	if errors.As(err, &e) {
		a.fail(w, r, e.status, e.message)
		return
	}
	if notFound(err) {
		a.fail(w, r, 404, "Not found.")
		return
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		a.fail(w, r, 422, "This value is already in use.")
		return
	}
	a.serverError(w, r, err)
}

type adminHandler func(http.ResponseWriter, *http.Request, *identity) error

func (a *App) registerAdmin(mux *http.ServeMux) {
	bind := func(pattern string, h adminHandler) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			actor, ok := a.requireAdmin(w, r)
			if !ok {
				return
			}
			if r.Method == "POST" {
				if err := r.ParseForm(); err != nil {
					a.fail(w, r, 400, "Invalid form.")
					return
				}
			}
			err := h(w, r, actor)
			if err != nil && r.Method == "POST" {
				status := 503
				var input adminError
				if errors.As(err, &input) {
					status = input.status
				} else if notFound(err) {
					status = 404
				}
				var target any
				switch {
				case strings.Contains(r.Pattern, "/users/"):
					target, _ = adminID[ids.UserID](r.PathValue("id"))
				case strings.Contains(r.Pattern, "/groups/"):
					target, _ = adminID[ids.GroupID](r.PathValue("id"))
				case strings.Contains(r.Pattern, "/clients/"):
					target, _ = adminID[ids.ClientID](r.PathValue("id"))
				}
				data := map[string]any{"action": r.Pattern, "target_id": target, "status": status}
				if auditErr := a.audit(r.Context(), a.Q, actor.User.ID, "AdminAction", data); auditErr != nil {
					err = auditErr
				}
			}
			a.adminResult(w, r, err)
		})
	}
	bind("GET /admin", a.adminHome)
	bind("GET /admin/audit", a.adminAudit)
	bind("GET /admin/access-log", a.adminAccess)
	for _, section := range []string{"users", "groups", "clients"} {
		s := section
		bind("GET /admin/"+s, func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminList(w, r, s) })
		bind("GET /admin/"+s+"/new", func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminForm(w, r, s) })
		bind("GET /admin/"+s+"/{id}", func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminForm(w, r, s) })
		bind("GET /admin/"+s+"/{id}/delete", func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminDeleteForm(w, r, v, s) })
		bind("POST /admin/"+s, func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminWrite(w, r, v, s) })
		bind("POST /admin/"+s+"/{id}", func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminWrite(w, r, v, s) })
		bind("POST /admin/"+s+"/{id}/delete", func(w http.ResponseWriter, r *http.Request, v *identity) error { return a.adminDelete(w, r, v, s) })
	}
	for _, action := range []string{"password", "role"} {
		action := action
		bind("GET /admin/users/{id}/"+action, func(w http.ResponseWriter, r *http.Request, v *identity) error {
			return a.adminUserActionForm(w, r, v, action)
		})
		bind("POST /admin/users/{id}/"+action, func(w http.ResponseWriter, r *http.Request, v *identity) error {
			return a.adminUserAction(w, r, v, action)
		})
	}
	bind("POST /admin/users/{id}/sessions/delete", a.adminRevokeSessions)
	bind("POST /admin/users/{id}/sessions/{session_id}/delete", a.adminRevokeSessions)
	bind("POST /admin/groups/{id}/members", a.adminMembership)
	bind("POST /admin/groups/{id}/members/{user_id}/remove", a.adminMembership)
	for _, suffix := range []string{"rotate-secret", "redirects", "redirects/{redirect_id}", "redirects/{redirect_id}/remove", "rules", "rules/{group_id}/remove"} {
		bind("POST /admin/clients/{id}/"+suffix, a.adminClientAction)
	}
}
func adminUser(ctx context.Context, q *db.Queries, id ids.UserID, lock bool) (db.User, error) {
	var u db.User
	var err error
	if lock {
		u, err = q.LockUser(ctx, id)
	} else {
		u, err = q.GetUser(ctx, id)
	}
	if err == nil && u.DeletedAt != nil {
		err = adminMissing()
	}
	return u, err
}
func adminGroup(ctx context.Context, q *db.Queries, id ids.GroupID, lock bool) (db.Group, error) {
	var u db.Group
	var err error
	if lock {
		u, err = q.LockGroup(ctx, id)
	} else {
		u, err = q.GetGroup(ctx, id)
	}
	if err == nil && u.DeletedAt != nil {
		err = adminMissing()
	}
	return u, err
}
func adminClient(ctx context.Context, q *db.Queries, id ids.ClientID, lock bool) (db.Client, error) {
	var u db.Client
	var err error
	if lock {
		u, err = q.LockClient(ctx, id)
	} else {
		u, err = q.GetClient(ctx, id)
	}
	if err == nil && u.DeletedAt != nil {
		err = adminMissing()
	}
	return u, err
}
func adminUserParams(u db.User) db.UpdateUserParams {
	return db.UpdateUserParams{ID: u.ID, Username: u.Username, Email: u.Email, Password: u.Password, Role: u.Role, Disabled: u.Disabled, MfaRevision: u.MfaRevision, MfaFailures: u.MfaFailures, MfaWindow: u.MfaWindow, WebauthnUserID: u.WebauthnUserID, DeletedAt: u.DeletedAt}
}
func adminClientParams(c db.Client) db.UpdateClientParams {
	return db.UpdateClientParams{ID: c.ID, Name: c.Name, Slug: c.Slug, ClientType: c.ClientType, ClientID: c.ClientID, ClientSecret: c.ClientSecret, SessionLifetimeS: c.SessionLifetimeS, RequirePkce: c.RequirePkce, DetailedLogging: c.DetailedLogging, AllowEventReports: c.AllowEventReports, DeletedAt: c.DeletedAt}
}
func adminRevokeUser(ctx context.Context, q *db.Queries, id ids.UserID) error {
	if err := q.AdminInvalidateUserLogins(ctx, id); err != nil {
		return err
	}
	if err := q.AdminDeleteUserCeremonies(ctx, id); err != nil {
		return err
	}
	return q.AdminDeleteUserSessions(ctx, id)
}
func (a *App) adminMutation(r *http.Request, actor *identity, target any, fn func(*db.Queries) error) error {
	return transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		if err := fn(q); err != nil {
			return err
		}
		if resolve, ok := target.(func() any); ok {
			target = resolve()
		}
		return a.audit(r.Context(), q, actor.User.ID, "AdminAction", map[string]any{"action": r.Pattern, "target_id": target, "status": 303})
	})
}
func adminSaved(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusSeeOther)
}
