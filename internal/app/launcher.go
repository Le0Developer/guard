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
