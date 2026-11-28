package app

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
)

func (a *App) registerUpstreamAdmin(mux *http.ServeMux) {
	bind := func(pattern string, h adminHandler) { a.bindAdmin(mux, pattern, h) }
	bind("GET /admin/providers", a.adminProviders)
	bind("GET /admin/providers/new", a.adminProviderForm)
	bind("GET /admin/providers/{id}", a.adminProviderForm)
	bind("POST /admin/providers", a.adminProviderWrite)
	bind("POST /admin/providers/{id}", a.adminProviderWrite)
	bind("GET /admin/providers/{id}/delete", a.adminProviderDeleteForm)
	bind("POST /admin/providers/{id}/delete", a.adminProviderDelete)
}
func (a *App) adminProviders(w http.ResponseWriter, r *http.Request, _ *identity) error {
	ps, err := a.Q.ListUpstreamProviders(r.Context())
	if err != nil {
		return err
	}
	rows := []adminRow{}
	for _, p := range ps {
		detail := p.Issuer
		if !p.Enabled {
			detail += " · Disabled"
		}
		rows = append(rows, adminRow{ID: fmt.Sprint(p.ID), Name: p.Name, Detail: detail})
	}
	a.page(w, r, "Upstream providers", adminUpstreamListTemplate, rows)
	return nil
}
func (a *App) adminProviderGet(r *http.Request) (db.UpstreamProvider, error) {
	id, err := adminID[ids.UpstreamProviderID](r.PathValue("id"))
	if err != nil {
		return db.UpstreamProvider{}, err
	}
	p, err := a.Q.GetUpstreamProvider(r.Context(), id)
	if err == nil && p.DeletedAt != nil {
		err = adminMissing()
	}
	return p, err
}
func (a *App) adminProviderForm(w http.ResponseWriter, r *http.Request, _ *identity) error {
	p := db.UpstreamProvider{ConfigurationMode: "oidc_discovery", ClientAuthMethod: "client_secret_basic", SubjectField: "sub", EmailField: "email", EmailVerifiedField: "email_verified", Scopes: "openid email", Pkce: true, SigningAlg: "RS256", Enabled: true, BackchannelLogoutEnabled: true}
	fresh := r.PathValue("id") == ""
	if !fresh {
		var err error
		p, err = a.adminProviderGet(r)
		if err != nil {
			return err
		}
	}
	p.ClientSecret = "" // Never pass credentials to a view.
	action := "/admin/providers"
	if !fresh {
		action += fmt.Sprint("/", p.ID)
	}
	a.page(w, r, "Upstream provider", adminUpstreamTemplate, map[string]any{"Target": p, "New": fresh, "Action": action, "Domain": strings.TrimRight(a.Config.Domain, "/")})
	return nil
}

// Keep route segments ASCII and leave room for a collision suffix.
func upstreamProviderSlug(name string, attempt int) string {
	var b strings.Builder
	separator := false
	for _, c := range strings.ToLower(name) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(c)
			separator = false
		} else {
			separator = true
		}
	}
	base := b.String()
	if base == "" {
		base = "provider"
	}
	if base == "password" || base == "mfa" {
		base = "provider-" + base
	}
	suffix := ""
	if attempt > 1 {
		suffix = fmt.Sprintf("-%d", attempt)
	}
	if len(base) > 63-len(suffix) {
		base = strings.TrimRight(base[:63-len(suffix)], "-")
	}
	return base + suffix
}

func (a *App) adminProviderWrite(w http.ResponseWriter, r *http.Request, actor *identity) error {
	fresh := r.PathValue("id") == ""
	old := db.UpstreamProvider{}
	if !fresh {
		var err error
		old, err = a.adminProviderGet(r)
		if err != nil {
			return err
		}
	}
	p := old
	p.Name = r.FormValue("name")
	p.Issuer = r.FormValue("issuer")
	p.ClientID = r.FormValue("client_id")
	p.Scopes = strings.Join(strings.Fields(r.FormValue("scopes")), " ")
	p.SigningAlg = old.SigningAlg
	p.Pkce = r.FormValue("pkce") != ""
	p.Enabled = r.FormValue("enabled") != ""
	p.BackchannelLogoutEnabled = r.FormValue("backchannel_logout_enabled") != ""
	if !fresh {
		if slug := r.FormValue("slug"); slug != "" && slug != old.Slug {
			return adminInvalid("The provider slug cannot be changed.")
		}
	}
	for _, v := range []struct {
		s, n string
		max  int
	}{{p.Name, "Name", 200}, {p.ClientID, "Client ID", 2000}} {
		if err := adminRequired(v.s, v.n, v.max); err != nil {
			return err
		}
	}
	if len(p.Scopes) > 2000 {
		return adminInvalid("Scopes must contain at most 2000 bytes.")
	}
	secret := r.FormValue("client_secret")
	if len(secret) > 16384 {
		return adminInvalid("Client secret is too long.")
	}
	if secret != "" {
		p.ClientSecret = secret
	}
	if fresh && p.ClientSecret == "" {
		return adminInvalid("Client secret is required.")
	}
	if err := a.configureUpstream(r, &p, old, fresh); err != nil {
		return err
	}
	setup := db.SetUpstreamProviderSetupParams{ConfigurationMode: p.ConfigurationMode, DiscoveryUrl: p.DiscoveryUrl, SubjectField: p.SubjectField, EmailField: p.EmailField, EmailVerifiedField: p.EmailVerifiedField, ClientAuthMethod: p.ClientAuthMethod}

	err := a.adminMutation(r, actor, func() any { return p.ID }, func(q *db.Queries, change *adminAuditChange) error {
		if fresh {
			for attempt := 1; ; attempt++ {
				p.Slug = upstreamProviderSlug(p.Name, attempt)
				var err error
				candidate, err := q.TryCreateUpstreamProvider(r.Context(), db.TryCreateUpstreamProviderParams{Slug: p.Slug, Name: p.Name, Issuer: p.Issuer, AuthorizeUrl: p.AuthorizeUrl, TokenUrl: p.TokenUrl, UserinfoUrl: p.UserinfoUrl, JwksUrl: p.JwksUrl, ClientID: p.ClientID, ClientSecret: p.ClientSecret, Scopes: p.Scopes, Pkce: p.Pkce, SigningAlg: p.SigningAlg, Enabled: p.Enabled, BackchannelLogoutEnabled: p.BackchannelLogoutEnabled})
				if notFound(err) {
					continue
				}
				if err != nil {
					return err
				}
				setup.ID = candidate.ID
				p, err = q.SetUpstreamProviderSetup(r.Context(), setup)
				return err
			}
		}
		locked, err := q.LockUpstreamProvider(r.Context(), p.ID)
		if err != nil {
			return err
		}
		if locked.DeletedAt != nil {
			return adminMissing()
		}
		if locked.Revision != old.Revision {
			return adminInvalid("Provider changed. Reload and try again.")
		}
		if err = change.capture(r.Context(), q, p.ID); err != nil {
			return err
		}
		if err = q.DeleteSessionsForProvider(r.Context(), p.ID); err != nil {
			return err
		}
		if err = q.DeleteProviderLoginSessions(r.Context(), p.ID); err != nil {
			return err
		}
		_, err = q.UpdateUpstreamProvider(r.Context(), db.UpdateUpstreamProviderParams{ID: p.ID, Name: p.Name, Issuer: p.Issuer, AuthorizeUrl: p.AuthorizeUrl, TokenUrl: p.TokenUrl, UserinfoUrl: p.UserinfoUrl, JwksUrl: p.JwksUrl, ClientID: p.ClientID, ClientSecret: p.ClientSecret, Scopes: p.Scopes, Pkce: p.Pkce, SigningAlg: p.SigningAlg, Enabled: p.Enabled, BackchannelLogoutEnabled: p.BackchannelLogoutEnabled})
		if err != nil {
			return err
		}
		setup.ID = p.ID
		_, err = q.SetUpstreamProviderSetup(r.Context(), setup)
		return err
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, fmt.Sprint("/admin/providers/", p.ID))
	return nil
}
func (a *App) adminProviderDeleteForm(w http.ResponseWriter, r *http.Request, _ *identity) error {
	p, err := a.adminProviderGet(r)
	if err != nil {
		return err
	}
	a.page(w, r, "Delete provider", adminUpstreamDeleteTemplate, adminRow{Name: p.Name})
	return nil
}
func (a *App) adminProviderDelete(w http.ResponseWriter, r *http.Request, actor *identity) error {
	id, err := adminID[ids.UpstreamProviderID](r.PathValue("id"))
	if err != nil {
		return err
	}
	err = a.adminMutation(r, actor, id, func(q *db.Queries, change *adminAuditChange) error {
		p, err := q.LockUpstreamProvider(r.Context(), id)
		if err != nil {
			return err
		}
		if p.DeletedAt != nil {
			return adminMissing()
		}
		if err = change.capture(r.Context(), q, p.ID); err != nil {
			return err
		}
		if err = q.DeleteSessionsForProvider(r.Context(), id); err != nil {
			return err
		}
		if err = q.DeleteProviderLoginSessions(r.Context(), id); err != nil {
			return err
		}
		return q.DeleteUpstreamProvider(r.Context(), id)
	})
	if err != nil {
		return err
	}
	adminSaved(w, r, "/admin/providers")
	return nil
}
