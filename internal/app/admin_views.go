package app

import (
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"net/http"
	"sort"
	"strings"
)

type adminRow struct {
	ID, Name, Detail        string
	Role, Identifier, Kind  string
	Disabled, LocalPassword bool
	Count                   int
}

func (a *App) adminHome(w http.ResponseWriter, r *http.Request, _ *identity) error {
	users, e := a.Q.ListUsers(r.Context())
	if e != nil {
		return e
	}
	groups, e := a.Q.ListGroups(r.Context())
	if e != nil {
		return e
	}
	clients, e := a.Q.ListClients(r.Context())
	if e != nil {
		return e
	}
	counts := map[string]int{"Users": 0, "Groups": 0, "Clients": 0}
	for _, u := range users {
		if u.DeletedAt == nil {
			counts["Users"]++
		}
	}
	for _, g := range groups {
		if g.DeletedAt == nil {
			counts["Groups"]++
		}
	}
	for _, c := range clients {
		if c.DeletedAt == nil {
			counts["Clients"]++
		}
	}
	a.page(w, r, "Administration", `<section aria-label="Directory"><div class="overflow-auto"><table class="table-striped table-hover"><thead><tr><th scope="col">Directory</th><th scope="col">Records</th><th scope="col">Manage</th></tr></thead><tbody><tr><th scope="row">Users</th><td>{{.Data.Users}}</td><td><a class="c-info" href="/admin/users">Manage users</a></td></tr><tr><th scope="row">Groups</th><td>{{.Data.Groups}}</td><td><a class="c-info" href="/admin/groups">Manage groups</a></td></tr><tr><th scope="row">Clients</th><td>{{.Data.Clients}}</td><td><a class="c-info" href="/admin/clients">Manage clients</a></td></tr></tbody></table></div></section>`, counts)
	return nil
}
func (a *App) adminList(w http.ResponseWriter, r *http.Request, section string) error {
	query := r.URL.Query().Get("q")
	rows := []adminRow{}
	ctx := r.Context()
	switch section {
	case "users":
		users, e := a.Q.ListUsers(ctx)
		if e != nil {
			return e
		}
		for _, u := range users {
			if u.DeletedAt != nil {
				continue
			}
			detail := u.Role
			if u.Disabled {
				detail += " · Disabled"
			}
			if u.Password != "" {
				detail += " · Password login"
			}
			rows = append(rows, adminRow{ID: fmt.Sprint(u.ID), Name: u.Username, Detail: detail, Role: u.Role, Disabled: u.Disabled, LocalPassword: u.Password != ""})
		}
	case "groups":
		groups, e := a.Q.ListGroups(ctx)
		if e != nil {
			return e
		}
		members, e := a.Q.ListGroupMembers(ctx)
		if e != nil {
			return e
		}
		for _, g := range groups {
			if g.DeletedAt != nil {
				continue
			}
			count := 0
			for _, m := range members {
				if m.GroupID == g.ID {
					count++
				}
			}
			rows = append(rows, adminRow{ID: fmt.Sprint(g.ID), Name: g.Name, Detail: fmt.Sprintf("%d members", count), Count: count})
		}
	case "clients":
		clients, e := a.Q.ListClients(ctx)
		if e != nil {
			return e
		}
		rules, e := a.Q.ListClientAccessRules(ctx)
		if e != nil {
			return e
		}
		for _, c := range clients {
			if c.DeletedAt != nil {
				continue
			}
			count := 0
			for _, rule := range rules {
				if rule.ClientID == c.ID {
					count++
				}
			}
			rows = append(rows, adminRow{ID: fmt.Sprint(c.ID), Name: c.Name, Identifier: c.ClientID, Kind: c.ClientType, Count: count, Detail: fmt.Sprintf("%s · %s · %d rules", c.ClientType, c.ClientID, count)})
		}
	}
	filtered := []adminRow{}
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Name), strings.ToLower(query)) {
			filtered = append(filtered, row)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name) })
	a.page(w, r, strings.ToUpper(section[:1])+section[1:], adminListTemplate, map[string]any{"Section": section, "Query": query, "Rows": filtered})
	return nil
}
func (a *App) adminForm(w http.ResponseWriter, r *http.Request, section string) error {
	data := map[string]any{"Section": section, "New": r.PathValue("id") == "", "Action": "/admin/" + section}
	raw := r.PathValue("id")
	ctx := r.Context()
	body := ""
	if raw != "" {
		data["Action"] = "/admin/" + section + "/" + raw
	}
	switch section {
	case "users":
		u := db.User{Role: "User"}
		sessions := []db.Session{}
		if raw != "" {
			id, e := adminID[ids.UserID](raw)
			if e != nil {
				return e
			}
			u, e = adminUser(ctx, a.Q, id, false)
			if e != nil {
				return e
			}
			sessions, e = a.Q.SessionsByUserId(ctx, id)
			if e != nil {
				return e
			}
		}
		data["Target"] = u
		data["Sessions"] = sessions
		body = adminUserTemplate
	case "groups":
		g := db.Group{}
		members, available := []db.User{}, []db.User{}
		if raw != "" {
			id, e := adminID[ids.GroupID](raw)
			if e != nil {
				return e
			}
			g, e = adminGroup(ctx, a.Q, id, false)
			if e != nil {
				return e
			}
			users, e := a.Q.ListUsers(ctx)
			if e != nil {
				return e
			}
			links, e := a.Q.ListGroupMembers(ctx)
			if e != nil {
				return e
			}
			for _, u := range users {
				if u.DeletedAt != nil {
					continue
				}
				member := false
				for _, m := range links {
					if m.GroupID == id && m.UserID == u.ID {
						member = true
						break
					}
				}
				if member {
					members = append(members, u)
				} else {
					available = append(available, u)
				}
			}
		}
		data["Target"] = g
		data["Members"] = members
		data["Available"] = available
		body = adminGroupTemplate
	case "clients":
		c := db.Client{ClientType: "Oidc", SessionLifetimeS: 64800, RequirePkce: true}
		redirects := []db.ClientRedirect{}
		rules := []db.ClientAccessRule{}
		if raw != "" {
			id, e := adminID[ids.ClientID](raw)
			if e != nil {
				return e
			}
			c, e = adminClient(ctx, a.Q, id, false)
			if e != nil {
				return e
			}
			redirects, e = a.Q.ClientRedirectsByClientId(ctx, id)
			if e != nil {
				return e
			}
			all, e := a.Q.ListClientAccessRules(ctx)
			if e != nil {
				return e
			}
			for _, rule := range all {
				if rule.ClientID == id {
					rules = append(rules, rule)
				}
			}
			sort.Slice(rules, func(i, j int) bool {
				if rules[i].Priority == rules[j].Priority {
					return rules[i].GroupID < rules[j].GroupID
				}
				return rules[i].Priority < rules[j].Priority
			})
		}
		groups, e := a.Q.ListGroups(ctx)
		if e != nil {
			return e
		}
		active := []db.Group{}
		for _, g := range groups {
			if g.DeletedAt == nil {
				active = append(active, g)
			}
		}
		data["Target"] = c
		data["Redirects"] = redirects
		data["Rules"] = rules
		data["Groups"] = active
		data["Domain"] = strings.TrimRight(a.Config.Domain, "/")
		body = adminClientTemplate
	}
	title := "Edit "
	if data["New"] == true {
		title = "Create "
	}
	title += strings.TrimSuffix(section, "s")
	a.page(w, r, title, body, data)
	return nil
}

const adminCSRF = `<input type="hidden" name="csrf_token" value="{{$.CSRF}}">`
const adminListTemplate = `<p><a class="btn btn-info" href="/admin/{{.Data.Section}}/new" role="button">Create {{if eq .Data.Section "users"}}user{{else if eq .Data.Section "groups"}}group{{else}}client{{end}}</a></p>
<form method="get" action="/admin/{{.Data.Section}}" role="search"><fieldset role="group"><input aria-label="Find {{.Data.Section}}" id="directory-search" type="search" name="q" value="{{.Data.Query}}" placeholder="Find {{.Data.Section}}"><button type="submit" class="btn btn-secondary">Search</button></fieldset></form>
{{if .Data.Rows}}<div class="overflow-auto" tabindex="0" role="region" aria-label="{{.Title}} directory"><table class="table-striped table-hover"><caption>{{len .Data.Rows}} {{.Data.Section}}</caption><thead><tr><th scope="col">{{if eq .Data.Section "users"}}Username{{else if eq .Data.Section "groups"}}Group{{else}}Name{{end}}</th>{{if eq .Data.Section "users"}}<th scope="col">Role</th><th scope="col">Status</th><th scope="col">Password login</th>{{else if eq .Data.Section "groups"}}<th scope="col">Members</th>{{else}}<th scope="col">Client ID</th><th scope="col">Type</th><th scope="col">Group rules</th>{{end}}<th scope="col">Actions</th></tr></thead><tbody>{{range .Data.Rows}}<tr><th scope="row"><a class="c-info" href="/admin/{{$.Data.Section}}/{{.ID}}">{{.Name}}</a></th>{{if eq $.Data.Section "users"}}<td>{{.Role}}</td><td>{{if .Disabled}}<span class="badge badge-warning">Disabled</span>{{else}}<span class="badge badge-success">Active</span>{{end}}</td><td>{{if .LocalPassword}}Enabled{{else}}Not set{{end}}</td>{{else if eq $.Data.Section "groups"}}<td>{{.Count}}</td>{{else}}<td><code>{{.Identifier}}</code></td><td>{{if eq .Kind "Oidc"}}OpenID Connect{{else}}Forward auth{{end}}</td><td>{{.Count}}</td>{{end}}<td><a class="c-info" href="/admin/{{$.Data.Section}}/{{.ID}}">Edit {{if eq $.Data.Section "users"}}user{{else if eq $.Data.Section "groups"}}group{{else}}client{{end}}</a></td></tr>{{end}}</tbody></table></div>{{else}}<article><h2>No {{.Data.Section}} found</h2><p>Try another search or create a record to get started.</p><a class="c-info" href="/admin/{{.Data.Section}}">Clear search</a></article>{{end}}`

const adminUserTemplate = `<p><a class="c-info" href="/admin/users">Back to users</a></p><form method="post" action="{{.Data.Action}}">` + adminCSRF + `<label for="username">Username</label><input id="username" name="username" value="{{.Data.Target.Username}}" maxlength="128" required><label for="email">Email</label><input id="email" name="email" type="email" value="{{.Data.Target.Email}}" maxlength="254">{{if .Data.New}}<label for="role">Role</label><select id="role" name="role"><option>User</option><option>Admin</option></select><label for="password">Password (optional)</label><input id="password" name="password" type="password" minlength="8" maxlength="72" autocomplete="new-password">{{end}}<label><input name="disabled" type="checkbox" {{if .Data.Target.Disabled}}checked{{end}}> Disable this account</label><button class="btn btn-info">Save details</button></form>{{if not .Data.New}}<hr><h2>Security</h2><p>Current role: {{.Data.Target.Role}}</p>{{if ne .User.ID .Data.Target.ID}}<p><a class="c-info" href="/admin/users/{{.Data.Target.ID}}/role">Change administrator access</a></p>{{end}}<p><a class="c-info" href="/admin/users/{{.Data.Target.ID}}/password">Reset password</a></p><p><a class="c-info" href="/admin/users/{{.Data.Target.ID}}/security">Manage authenticators and backup codes</a></p><h2>Sessions</h2><div class="overflow-auto"><table class="table-striped"><thead><tr><th>Session</th><th>Created</th><th>Expires</th><th>Action</th></tr></thead><tbody>{{range .Data.Sessions}}<tr><td>{{.ID}}</td><td>{{.CreatedAt}}</td><td>{{.ExpiresAt}}</td><td><form method="post" action="/admin/users/{{$.Data.Target.ID}}/sessions/{{.ID}}/delete">` + adminCSRF + `<button class="btn btn-error btn-outline">Revoke session</button></form></td></tr>{{else}}<tr><td colspan="4">No active sessions.</td></tr>{{end}}</tbody></table></div><form method="post" action="/admin/users/{{.Data.Target.ID}}/sessions/delete">` + adminCSRF + `<button class="btn btn-error">Revoke all sessions</button></form>{{if ne .User.ID .Data.Target.ID}}<p><a class="btn btn-error btn-outline" href="/admin/users/{{.Data.Target.ID}}/delete">Delete user</a></p>{{end}}{{end}}`
const adminUserActionTemplate = `<p>Account: <strong>{{.Data.Target.Username}}</strong></p><form method="post">` + adminCSRF + `{{if eq .Data.Action "password"}}<p>This changes the password and revokes all sessions.</p><label for="password">New password</label><input id="password" name="password" type="password" minlength="8" maxlength="72" autocomplete="new-password" required><label for="confirm_password">Confirm password</label><input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>{{else}}<p>Current role: {{.Data.Target.Role}}. Changing this role revokes all sessions.</p><input type="hidden" name="current_role" value="{{.Data.Target.Role}}"><input type="hidden" name="role" value="{{if eq .Data.Target.Role "Admin"}}User{{else}}Admin{{end}}"><p>{{if eq .Data.Target.Role "Admin"}}Remove{{else}}Grant{{end}} administrator access?</p>{{end}}<button class="btn btn-warning">Confirm change</button><a class="c-info" href="/admin/users/{{.Data.Target.ID}}">Cancel</a></form>`
const adminDeleteTemplate = `<p>Delete <strong>{{.Data.Name}}</strong>?</p><p>Access and related memberships or client credentials will be removed. The record is retained for audit history.</p><form method="post">` + adminCSRF + `<button class="btn btn-error">Confirm deletion</button> <a class="c-info" href="/admin/{{.Data.Section}}/{{.Data.ID}}">Cancel</a></form>`
const adminGroupTemplate = `<p><a class="c-info" href="/admin/groups">Back to groups</a></p><form method="post" action="{{.Data.Action}}">` + adminCSRF + `<label for="name">Group name</label><input id="name" name="name" value="{{.Data.Target.Name}}" maxlength="200" required><button class="btn btn-info">Save group</button></form>{{if not .Data.New}}<h2>Members</h2><div class="overflow-auto"><table class="table-striped"><thead><tr><th>User</th><th>Action</th></tr></thead><tbody>{{range .Data.Members}}<tr><td><a class="c-info" href="/admin/users/{{.ID}}">{{.Username}}</a></td><td><form method="post" action="/admin/groups/{{$.Data.Target.ID}}/members/{{.ID}}/remove">` + adminCSRF + `<button class="btn btn-secondary btn-outline">Remove</button></form></td></tr>{{else}}<tr><td colspan="2">No members.</td></tr>{{end}}</tbody></table></div><form method="post" action="/admin/groups/{{.Data.Target.ID}}/members">` + adminCSRF + `<label for="user_id">Add a member</label><select id="user_id" name="user_id" required>{{range .Data.Available}}<option value="{{.ID}}">{{.Username}}</option>{{end}}</select><button class="btn btn-info">Add member</button></form><p><a class="btn btn-error btn-outline" href="/admin/groups/{{.Data.Target.ID}}/delete">Delete group</a></p>{{end}}`

const adminClientTemplate = `<p><a class="c-info" href="/admin/clients">Back to clients</a></p><form method="post" action="{{.Data.Action}}">` + adminCSRF + `<label for="name">Name</label><input id="name" name="name" value="{{.Data.Target.Name}}" maxlength="200" required><label for="client_type">Client type</label><select id="client_type" name="client_type"><option value="Oidc" {{if eq .Data.Target.ClientType "Oidc"}}selected{{end}}>OpenID Connect</option><option value="ForwardAuth" {{if eq .Data.Target.ClientType "ForwardAuth"}}selected{{end}}>Forward auth</option></select><label for="lifetime">Session lifetime (seconds)</label><input id="lifetime" name="session_lifetime_s" type="number" value="{{.Data.Target.SessionLifetimeS}}" min="300" max="2592000" required><fieldset><label><input type="checkbox" name="require_pkce" {{if .Data.Target.RequirePkce}}checked{{end}}> Require PKCE</label></fieldset><fieldset><legend>OpenID Connect back-channel logout</legend><label for="backchannel-logout-uri">Logout URI (optional)</label><input id="backchannel-logout-uri" name="backchannel_logout_uri" type="url" maxlength="2048" value="{{.Data.Target.BackchannelLogoutUri}}"><label><input type="checkbox" name="backchannel_logout_session_required" {{if .Data.Target.BackchannelLogoutSessionRequired}}checked{{end}}> Require session identifier (sid)</label></fieldset><fieldset><legend>Access journal</legend><label><input type="checkbox" name="detailed_logging" {{if .Data.Target.DetailedLogging}}checked{{end}}> Record every authentication request</label><label><input type="checkbox" name="allow_event_reports" {{if .Data.Target.AllowEventReports}}checked{{end}}> Accept session-bound application events</label></fieldset><button class="btn btn-info">Save client</button></form>{{if not .Data.New}}<hr><h2>Credentials</h2><label for="client-id">Client ID</label><input id="client-id" readonly value="{{.Data.Target.ClientID}}"><details><summary>Show client secret</summary><label for="client-secret">Client secret</label><input id="client-secret" readonly value="{{.Data.Target.ClientSecret}}"></details><details><summary>Rotate client secret</summary><p>The previous secret will stop working. Update the application configuration.</p><form method="post" action="/admin/clients/{{.Data.Target.ID}}/rotate-secret">` + adminCSRF + `<label><input type="checkbox" name="confirm" value="rotate" required> I am ready to replace the existing secret.</label><button class="btn btn-warning">Generate new secret</button></form></details><h2>Endpoints</h2>{{if eq .Data.Target.ClientType "Oidc"}}<label>Issuer<input readonly value="{{.Data.Domain}}/oauth2/{{.Data.Target.Slug}}"></label><label>OpenID configuration<input readonly value="{{.Data.Domain}}/oauth2/{{.Data.Target.Slug}}/.well-known/openid-configuration"></label><label>JWKS<input readonly value="{{.Data.Domain}}/oauth2/{{.Data.Target.Slug}}/jwks"></label><label>Authorization<input readonly value="{{.Data.Domain}}/oauth2/authorize"></label><label>Token<input readonly value="{{.Data.Domain}}/oauth2/token"></label><label>Introspection<input readonly value="{{.Data.Domain}}/oauth2/introspect"></label><label>Userinfo<input readonly value="{{.Data.Domain}}/oauth2/userinfo"></label><label>Revocation<input readonly value="{{.Data.Domain}}/oauth2/revoke"></label>{{else}}<p>Configure your reverse proxy to use Guard's private ForwardAuth endpoint and this client ID.</p>{{end}}<label>Application events<input readonly value="{{.Data.Domain}}/oauth2/event"></label><hr><section id="redirect-uris"><h2>{{if eq .Data.Target.ClientType "ForwardAuth"}}Allowed origins{{else}}Redirect URIs{{end}}</h2>{{range .Data.Redirects}}<form class="redirect-uri-row" method="post" action="/admin/clients/{{$.Data.Target.ID}}/redirects/{{.ID}}">` + adminCSRF + `<label>Registered URI<input name="redirect_uri" value="{{.RedirectUri}}" maxlength="2048" required></label><div class="redirect-uri-actions"><button type="submit" class="btn btn-secondary">Save URI</button><button type="submit" class="btn btn-error btn-outline" formaction="/admin/clients/{{$.Data.Target.ID}}/redirects/{{.ID}}/remove" formnovalidate>Remove URI</button></div></form>{{else}}<p>No URIs registered.</p>{{end}}<form method="post" action="/admin/clients/{{.Data.Target.ID}}/redirects">` + adminCSRF + `<label>Add URI<input name="redirect_uri" type="url" maxlength="2048" required></label><small>{{if eq .Data.Target.ClientType "ForwardAuth"}}Enter an exact origin: scheme, host and optional port.{{else}}Enter an exact callback URL. Wildcards and fragments are forbidden.{{end}}</small><button class="btn btn-info">Add URI</button></form></section><hr><h2>Group access rules</h2><p>Lower priority numbers win; Deny wins a tie. Without rules all users have access. With rules, users require a matching Allow.</p><div class="overflow-auto"><table class="table-striped"><thead><tr><th>Group</th><th>Priority</th><th>Decision</th><th>Action</th></tr></thead><tbody>{{range .Data.Rules}}<tr><td><a class="c-info" href="/admin/groups/{{.GroupID}}">Group {{.GroupID}}</a></td><td>{{.Priority}}</td><td>{{.AccessControl}}</td><td><form method="post" action="/admin/clients/{{$.Data.Target.ID}}/rules/{{.GroupID}}/remove">` + adminCSRF + `<button class="btn btn-secondary">Remove rule</button></form></td></tr>{{else}}<tr><td colspan="4">No group rules configured.</td></tr>{{end}}</tbody></table></div><form method="post" action="/admin/clients/{{.Data.Target.ID}}/rules">` + adminCSRF + `<label>Group<select name="group_id" required>{{range .Data.Groups}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></label><label>Priority<input name="priority" type="number" min="-32768" max="32767" value="0" required></label><label>Decision<select name="access_control"><option value="allow">Allow</option><option value="deny">Deny</option></select></label><button class="btn btn-info">Add or replace rule</button></form><p><a class="btn btn-error btn-outline" href="/admin/clients/{{.Data.Target.ID}}/delete">Delete client</a></p>{{else}}<p>Save the client to generate credentials and configure redirects and group rules.</p>{{end}}`
