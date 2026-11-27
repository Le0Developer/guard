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
	a.page(w, r, "Administration", adminOverviewTemplate, counts)
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
