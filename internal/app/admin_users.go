package app

import (
	"context"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func (a *App) adminWrite(w http.ResponseWriter, r *http.Request, actor *identity, section string) error {
	if section == "clients" {
		return a.adminWriteClient(w, r, actor)
	}
	ctx := r.Context()
	raw := r.PathValue("id")
	if section == "groups" {
		var id ids.GroupID
		var err error
		if raw != "" {
			id, err = adminID[ids.GroupID](raw)
			if err != nil {
				return err
			}
		}
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if err = adminRequired(name, "Group name", 200); err != nil {
			return err
		}
		err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
			groups, e := q.ListGroups(ctx)
			if e != nil {
				return e
			}
			for _, g := range groups {
				if g.DeletedAt == nil && g.ID != id && strings.EqualFold(g.Name, name) {
					return adminInvalid("A group with this name already exists.")
				}
			}
			if id == 0 {
				g, e := q.CreateGroup(ctx, db.CreateGroupParams{Name: name, DeletedAt: nil})
				id = g.ID
				return e
			}
			g, e := adminGroup(ctx, q, id, true)
			if e != nil {
				return e
			}
			_, e = q.UpdateGroup(ctx, db.UpdateGroupParams{ID: id, Name: name, DeletedAt: g.DeletedAt})
			return e
		})
		if err != nil {
			return err
		}
		adminSaved(w, r, "/admin/groups/"+strconv.FormatInt(int64(id), 10))
		return nil
	}
	var id ids.UserID
	var err error
	if raw != "" {
		id, err = adminID[ids.UserID](raw)
		if err != nil {
			return err
		}
	}
	username, email := strings.TrimSpace(r.PostForm.Get("username")), strings.TrimSpace(r.PostForm.Get("email"))
	disabled := r.PostForm.Has("disabled")
	if err = adminRequired(username, "Username", 128); err != nil {
		return err
	}
	if email != "" && (len(email) > 254 || strings.Count(email, "@") != 1 || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") || strings.IndexFunc(email, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0) {
		return adminInvalid("Enter a valid email address.")
	}
	if raw != "" && id == actor.User.ID && disabled {
		return adminInvalid("You cannot disable your own account.")
	}
	role := r.PostForm.Get("role")
	password := r.PostForm.Get("password")
	hash := ""
	if raw != "" && (r.PostForm.Has("role") || r.PostForm.Has("password")) {
		return adminInvalid("Use the separate role or password action to make that change.")
	}
	if raw == "" {
		if role != "Admin" && role != "User" {
			return adminInvalid("Choose User or Admin.")
		}
		if password != "" {
			if len(password) < 8 || len(password) > 72 {
				return adminInvalid("Passwords must be between 8 and 72 bytes.")
			}
			hash, err = security.HashPassword(password)
			if err != nil {
				return err
			}
		}
	}
	err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
		if raw == "" {
			u, e := q.CreateUser(ctx, db.CreateUserParams{Username: username, Email: email, Password: hash, Role: role, Disabled: disabled, MfaRevision: 0, MfaFailures: 0, MfaWindow: nil, WebauthnUserID: []byte(security.Token()), DeletedAt: nil})
			id = u.ID
			return e
		}
		u, e := adminUser(ctx, q, id, true)
		if e != nil {
			return e
		}
		p := adminUserParams(u)
		p.Username = username
		p.Email = email
		p.Disabled = disabled
		if _, e = q.UpdateUser(ctx, p); e != nil {
			return e
		}
		if disabled {
			return adminRevokeUser(ctx, q, id)
		}
		return nil
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/users")
	return nil
}
func (a *App) adminUserActionForm(w http.ResponseWriter, r *http.Request, actor *identity, action string) error {
	id, err := adminID[ids.UserID](r.PathValue("id"))
	if err != nil {
		return err
	}
	u, err := adminUser(r.Context(), a.Q, id, false)
	if err != nil {
		return err
	}
	if action == "role" && id == actor.User.ID {
		return adminInvalid("You cannot change your own administrator role.")
	}
	a.page(w, r, "Confirm "+action+" change", adminUserActionTemplate, map[string]any{"Target": u, "Action": action})
	return nil
}
func (a *App) adminUserAction(w http.ResponseWriter, r *http.Request, actor *identity, action string) error {
	id, err := adminID[ids.UserID](r.PathValue("id"))
	if err != nil {
		return err
	}
	hash := ""
	if action == "password" {
		p := r.PostForm.Get("password")
		if len(p) < 8 || len(p) > 72 {
			return adminInvalid("Passwords must be between 8 and 72 bytes.")
		}
		if p != r.PostForm.Get("confirm_password") {
			return adminInvalid("The passwords do not match.")
		}
		hash, err = security.HashPassword(p)
		if err != nil {
			return err
		}
	} else if id == actor.User.ID {
		return adminInvalid("You cannot change your own administrator role.")
	}
	err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
		u, e := adminUser(r.Context(), q, id, true)
		if e != nil {
			return e
		}
		p := adminUserParams(u)
		if action == "password" {
			p.Password = hash
		} else {
			role := r.PostForm.Get("role")
			if role != "Admin" && role != "User" {
				return adminInvalid("Invalid role.")
			}
			if r.PostForm.Get("current_role") != u.Role || role == u.Role {
				return adminInvalid("The user's role has changed. Review the current role before confirming.")
			}
			p.Role = role
		}
		if _, e = q.UpdateUser(r.Context(), p); e != nil {
			return e
		}
		return adminRevokeUser(r.Context(), q, id)
	})
	if err != nil {
		return err
	}
	path := "/admin/users/" + r.PathValue("id")
	if id == actor.User.ID {
		path = "/login"
	}
	adminSaved(w, r, path)
	return nil
}
func (a *App) adminRevokeSessions(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, err := adminID[ids.UserID](r.PathValue("id"))
	if err != nil {
		return err
	}
	current := id == actor.User.ID
	err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
		if _, e := adminUser(r.Context(), q, id, true); e != nil {
			return e
		}
		if raw := r.PathValue("session_id"); raw != "" {
			sid, e := adminID[ids.SessionID](raw)
			if e != nil {
				return e
			}
			s, e := q.LockSession(r.Context(), sid)
			if e != nil {
				return e
			}
			if s.UserID != id {
				return adminMissing()
			}
			current = sid == actor.Session.ID
			return q.DeleteSession(r.Context(), sid)
		}
		return adminRevokeUser(r.Context(), q, id)
	})
	if err != nil {
		return err
	}
	path := "/admin/users/" + r.PathValue("id")
	if current {
		path = "/login"
	}
	adminSaved(w, r, path)
	return nil
}
func (a *App) adminMembership(w http.ResponseWriter, r *http.Request, actor *identity) error {
	gid, err := adminID[ids.GroupID](r.PathValue("id"))
	if err != nil {
		return err
	}
	raw := r.PathValue("user_id")
	remove := raw != ""
	if !remove {
		raw = r.PostForm.Get("user_id")
	}
	uid, err := adminID[ids.UserID](raw)
	if err != nil {
		return adminInvalid("Choose a user.")
	}
	err = a.adminMutation(r, actor, gid, func(q *db.Queries) error {
		if _, e := adminUser(r.Context(), q, uid, true); e != nil {
			return e
		}
		if _, e := adminGroup(r.Context(), q, gid, true); e != nil {
			return e
		}
		if remove {
			return q.DeleteGroupMember(r.Context(), db.DeleteGroupMemberParams{GroupID: gid, UserID: uid})
		}
		return q.AdminAddMember(r.Context(), db.AdminAddMemberParams{GroupID: gid, UserID: uid})
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/groups/"+r.PathValue("id"))
	return nil
}
func (a *App) adminDeleteForm(w http.ResponseWriter, r *http.Request, actor *identity, section string) error {
	name := ""
	raw := r.PathValue("id")
	switch section {
	case "users":
		id, e := adminID[ids.UserID](raw)
		if e != nil {
			return e
		}
		if id == actor.User.ID {
			return adminInvalid("You cannot delete your own account.")
		}
		u, e := adminUser(r.Context(), a.Q, id, false)
		if e != nil {
			return e
		}
		name = u.Username
	case "groups":
		id, e := adminID[ids.GroupID](raw)
		if e != nil {
			return e
		}
		g, e := adminGroup(r.Context(), a.Q, id, false)
		if e != nil {
			return e
		}
		name = g.Name
	case "clients":
		id, e := adminID[ids.ClientID](raw)
		if e != nil {
			return e
		}
		c, e := adminClient(r.Context(), a.Q, id, false)
		if e != nil {
			return e
		}
		name = c.Name
	}
	a.page(w, r, "Confirm deletion", adminDeleteTemplate, map[string]any{"Name": name, "Section": section, "ID": raw})
	return nil
}
func (a *App) adminDelete(w http.ResponseWriter, r *http.Request, actor *identity, section string) error {
	ctx := r.Context()
	raw := r.PathValue("id")
	now := time.Now()
	err := a.adminMutation(r, actor, raw, func(q *db.Queries) error {
		switch section {
		case "users":
			id, e := adminID[ids.UserID](raw)
			if e != nil {
				return e
			}
			if id == actor.User.ID {
				return adminInvalid("You cannot delete your own account.")
			}
			u, e := adminUser(ctx, q, id, true)
			if e != nil {
				return e
			}
			p := adminUserParams(u)
			p.Disabled = true
			p.DeletedAt = &now
			if _, e = q.UpdateUser(ctx, p); e != nil {
				return e
			}
			if e = adminRevokeUser(ctx, q, id); e != nil {
				return e
			}
			return q.AdminDeleteUserMemberships(ctx, id)
		case "groups":
			id, e := adminID[ids.GroupID](raw)
			if e != nil {
				return e
			}
			// Acquire the table lock before any group or client row locks. This
			// includes clients created concurrently and matches client-first edits.
			if e := q.LockClientsForGroupDeletion(ctx); e != nil {
				return e
			}
			clients, e := q.ListClients(ctx)
			if e != nil {
				return e
			}
			g, e := adminGroup(ctx, q, id, true)
			if e != nil {
				return e
			}
			for _, c := range clients {
				rules, e := q.ClientAccessRulesByClientId(ctx, c.ID)
				if e != nil {
					return e
				}
				if len(rules) == 1 && rules[0].GroupID == id && c.DeletedAt == nil && !c.Disabled {
					if _, e = q.SetClientDisabled(ctx, db.SetClientDisabledParams{ID: c.ID, Disabled: true}); e != nil {
						return e
					}
					if e = a.audit(ctx, q, actor.User.ID, "ClientDisabled", map[string]any{"client_id": c.ID, "group_id": id, "reason": "last access rule removed"}); e != nil {
						return e
					}
				}
			}
			if e = q.AdminDeleteGroupRules(ctx, id); e != nil {
				return e
			}
			if e = q.AdminDeleteGroupMemberships(ctx, id); e != nil {
				return e
			}
			_, e = q.UpdateGroup(ctx, db.UpdateGroupParams{ID: id, Name: g.Name, DeletedAt: &now})
			return e
		case "clients":
			id, e := adminID[ids.ClientID](raw)
			if e != nil {
				return e
			}
			c, e := adminClient(ctx, q, id, true)
			if e != nil {
				return e
			}
			for _, fn := range []func(context.Context, ids.ClientID) error{q.AdminDeleteClientRules, q.AdminDeleteClientRedirects, q.AdminDeleteClientCodes, q.AdminDeleteClientRequests, q.AdminDeleteClientSessions} {
				if e = fn(ctx, id); e != nil {
					return e
				}
			}
			p := adminClientParams(c)
			p.DeletedAt = &now
			_, e = q.UpdateClient(ctx, p)
			return e
		}
		return adminMissing()
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/"+section)
	return nil
}
