package app

import (
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"strconv"
	"strings"
)

func (a *App) adminWriteClient(w http.ResponseWriter, r *http.Request, actor *identity) error {
	var id ids.ClientID
	var err error
	if raw := r.PathValue("id"); raw != "" {
		id, err = adminID[ids.ClientID](raw)
		if err != nil {
			return err
		}
	}
	name, kind := strings.TrimSpace(r.PostForm.Get("name")), r.PostForm.Get("client_type")
	if err = adminRequired(name, "Client name", 200); err != nil {
		return err
	}
	if kind != "Oidc" && kind != "ForwardAuth" && kind != "Saml" {
		return adminInvalid("Choose OpenID Connect, Forward auth or SAML.")
	}
	logoutURI := r.PostForm.Get("backchannel_logout_uri")
	logoutRequired := r.PostForm.Has("backchannel_logout_session_required")
	if kind != "Oidc" {
		logoutURI, logoutRequired = "", false
	} else if err := validateLogoutURI(logoutURI); err != nil {
		return adminInvalid(err.Error())
	}
	lifetime, e := strconv.ParseInt(r.PostForm.Get("session_lifetime_s"), 10, 32)
	if e != nil || lifetime < 300 || lifetime > 2592000 {
		return adminInvalid("Session lifetime must be 300–2592000 seconds.")
	}
	err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
		var c db.Client
		var e error
		var old map[string]bool
		if id != 0 {
			c, e = adminClient(r.Context(), q, id, true)
			if e != nil {
				return e
			}
			old = map[string]bool{"detailed_logging": c.DetailedLogging, "allow_event_reports": c.AllowEventReports}
			if c.ClientType != kind {
				if c.ClientType == "Saml" || kind == "Saml" {
					return adminInvalid("Create a new client when switching into or out of SAML.")
				}
				redirects, e := q.ClientRedirectsByClientId(r.Context(), id)
				if e != nil {
					return e
				}
				for _, rd := range redirects {
					if kind == "ForwardAuth" {
						origin, e := security.Origin(rd.RedirectUri)
						if e != nil || origin != rd.RedirectUri {
							return adminInvalid("Remove callback URLs before changing this client to Forward auth.")
						}
					}
				}
			}
		}
		if id == 0 {
			c, e = q.CreateClient(r.Context(), db.CreateClientParams{Name: name, Slug: security.Token(), ClientID: security.Token(), ClientSecret: security.Token(), ClientType: kind, SessionLifetimeS: int32(lifetime), RequirePkce: kind != "Saml" && r.PostForm.Has("require_pkce"), DetailedLogging: r.PostForm.Has("detailed_logging"), AllowEventReports: kind != "Saml" && r.PostForm.Has("allow_event_reports"), DeletedAt: nil})
			id = c.ID
		} else {
			p := adminClientParams(c)
			p.Name = name
			p.ClientType = kind
			p.SessionLifetimeS = int32(lifetime)
			p.RequirePkce = kind != "Saml" && r.PostForm.Has("require_pkce")
			p.DetailedLogging = r.PostForm.Has("detailed_logging")
			p.AllowEventReports = kind != "Saml" && r.PostForm.Has("allow_event_reports")
			c, e = q.UpdateClient(r.Context(), p)
		}
		if e != nil {
			return e
		}
		c, e = q.SetClientDisabled(r.Context(), db.SetClientDisabledParams{ID: id, Disabled: r.PostForm.Has("disabled")})
		if e != nil {
			return e
		}
		c, e = q.SetClientBackchannelLogout(r.Context(), db.SetClientBackchannelLogoutParams{ID: id, BackchannelLogoutUri: logoutURI, BackchannelLogoutSessionRequired: logoutRequired})
		if e != nil {
			return e
		}
		if old != nil && old["detailed_logging"] == c.DetailedLogging && old["allow_event_reports"] == c.AllowEventReports || old == nil && !c.DetailedLogging && !c.AllowEventReports {
			return nil
		}
		settings := map[string]any{"client_id": id, "previous": old, "detailed_logging": c.DetailedLogging, "allow_event_reports": c.AllowEventReports}
		if e = a.audit(r.Context(), q, actor.User.ID, "ClientLoggingConfiguration", settings); e != nil {
			return e
		}
		_, e = a.persistAccess(r.Context(), q, c, &actor.User.ID, nil, "configuration", "configuration:"+security.Token(), map[string]any{"client_name": c.Name, "client_identifier": c.ClientID, "endpoint": "/admin/clients", "decision": "settings_changed", "settings": settings})
		return e
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/clients/"+strconv.FormatInt(int64(id), 10))
	return nil
}
func (a *App) adminClientAction(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, err := adminID[ids.ClientID](r.PathValue("id"))
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = a.adminMutation(r, actor, func() any { return id }, func(q *db.Queries) error {
		c, e := adminClient(ctx, q, id, true)
		if e != nil {
			return e
		}
		if c.ClientType == "Saml" && !strings.Contains(r.URL.Path, "/rules") {
			return adminInvalid("Use SAML configuration to manage this application.")
		}
		if strings.HasSuffix(r.URL.Path, "/rotate-secret") {
			if r.PostForm.Get("confirm") != "rotate" {
				return adminInvalid("Confirm that you want to rotate the secret.")
			}
			p := adminClientParams(c)
			p.ClientSecret = security.Token()
			_, e = q.UpdateClient(ctx, p)
			return e
		}
		if strings.Contains(r.URL.Path, "/rules") {
			raw := r.PathValue("group_id")
			remove := raw != ""
			if !remove {
				raw = r.PostForm.Get("group_id")
			}
			gid, e := adminID[ids.GroupID](raw)
			if e != nil {
				return adminInvalid("Choose a group.")
			}
			if _, e = adminGroup(ctx, q, gid, true); e != nil {
				return e
			}
			if remove {
				return q.DeleteClientAccessRule(ctx, db.DeleteClientAccessRuleParams{ClientID: id, GroupID: gid})
			}
			priority, e := strconv.ParseInt(r.PostForm.Get("priority"), 10, 16)
			if e != nil {
				return adminInvalid("Priority must be a whole number between -32768 and 32767.")
			}
			access := r.PostForm.Get("access_control")
			switch access {
			case "allow":
				access = "Allow"
			case "deny":
				access = "Deny"
			default:
				return adminInvalid("Choose Allow or Deny.")
			}
			return q.AdminSaveRule(ctx, db.AdminSaveRuleParams{ClientID: id, GroupID: gid, Priority: int16(priority), AccessControl: access})
		}
		var rid ids.ClientRedirectID
		if raw := r.PathValue("redirect_id"); raw != "" {
			rid, e = adminID[ids.ClientRedirectID](raw)
			if e != nil {
				return e
			}
			rd, e := q.GetClientRedirect(ctx, rid)
			if e != nil {
				return e
			}
			if rd.ClientID != id {
				return adminMissing()
			}
		}
		if strings.HasSuffix(r.URL.Path, "/remove") {
			return q.DeleteClientRedirect(ctx, rid)
		}
		uri := r.PostForm.Get("redirect_uri")
		if e = adminRedirectError(uri); e != nil {
			return e
		}
		if c.ClientType == "ForwardAuth" {
			uri, e = security.Origin(uri)
			if e != nil {
				return adminInvalid("Enter an application origin with only scheme, host and optional port.")
			}
		}
		redirects, e := q.ClientRedirectsByClientId(ctx, id)
		if e != nil {
			return e
		}
		for _, rd := range redirects {
			if rd.ID != rid && rd.RedirectUri == uri {
				return adminInvalid("This URI is already registered for this client.")
			}
		}
		if rid != 0 {
			_, e = q.UpdateClientRedirect(ctx, db.UpdateClientRedirectParams{ID: rid, ClientID: id, RedirectUri: uri})
		} else {
			_, e = q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: id, RedirectUri: uri})
		}
		return e
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/clients/"+r.PathValue("id"))
	return nil
}
