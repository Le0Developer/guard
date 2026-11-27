package app

import (
	"net/http"
	"sort"
	"strings"

	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
)

type launcherApp struct{ Name, URL string }

func (a *App) launcherApps(r *http.Request, user ids.UserID) ([]launcherApp, error) {
	clients, err := a.Q.ListClients(r.Context())
	if err != nil {
		return nil, err
	}
	apps := []launcherApp{}
	for _, client := range clients {
		if client.DeletedAt != nil {
			continue
		}
		allowed, err := a.permitted(r.Context(), a.Q, client.ID, user)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		redirects, err := a.Q.ClientRedirectsByClientId(r.Context(), client.ID)
		if err != nil {
			return nil, err
		}
		launchURL := ""
		if len(redirects) > 0 {
			// OIDC callback paths are not app entry points. Launch the first URI's origin.
			if parsed, err := security.URL(redirects[0].RedirectUri); err == nil {
				launchURL, _ = security.Origin(parsed.Scheme + "://" + parsed.Host)
			}
		}
		apps = append(apps, launcherApp{Name: client.Name, URL: launchURL})
	}
	sort.SliceStable(apps, func(i, j int) bool { return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name) })
	return apps, nil
}

const homeTemplate = `<section aria-labelledby="launcher-heading"><h2 id="launcher-heading">App launcher</h2>
{{if .Data.Apps}}<ul class="app-launcher">{{range .Data.Apps}}<li>{{if .URL}}<a class="btn btn-info btn-outline" role="button" href="{{.URL}}">{{.Name}}</a>{{else}}<span class="btn btn-secondary btn-outline" aria-disabled="true" title="Launch link unavailable">{{.Name}}</span>{{end}}</li>{{end}}</ul>{{else}}<p>No apps available.</p>{{end}}</section>
<hr><p><a class="btn btn-info" role="button" href="/security">Manage security</a></p>
<div class="row"><section class="col-12"><dl><dt>Username</dt><dd>{{.Data.Account.Username}}</dd><dt>Role</dt><dd>{{if eq .Data.Account.Role "Admin"}}Administrator{{else}}User{{end}}</dd><dt>Sign-in access</dt><dd><span class="badge badge-success">Active</span></dd><dt>Account created</dt><dd>{{.Data.Account.CreatedAt.Format "2006-01-02 15:04:05 UTC"}}</dd></dl></section></div>`
