package app

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/le0developer/guard/internal/db"
)

type userinfoPreviewClient struct {
	ID, Name string
	Selected bool
}

type userinfoPreview struct {
	Clients            []userinfoPreviewClient
	Scope, JSON, Error string
}

func (a *App) userinfoSimulation(r *http.Request, user db.User) (userinfoPreview, error) {
	query := r.URL.Query()
	preview := userinfoPreview{Scope: "openid profile email groups"}
	if query.Has("preview_scope") {
		preview.Scope = strings.Join(strings.Fields(query.Get("preview_scope")), " ")
	}
	clients, err := a.Q.ListClients(r.Context())
	if err != nil {
		return preview, err
	}
	selectedID := query.Get("preview_client")
	var selected *db.Client
	for _, client := range clients {
		if client.DeletedAt != nil || client.ClientType != "Oidc" {
			continue
		}
		allowed, err := a.permitted(r.Context(), a.Q, client.ID, user.ID)
		if err != nil {
			return preview, err
		}
		if !allowed {
			continue
		}
		if selectedID == "" {
			selectedID = client.ClientID
		}
		active := client.ClientID == selectedID
		preview.Clients = append(preview.Clients, userinfoPreviewClient{ID: client.ClientID, Name: client.Name, Selected: active})
		if active {
			selected = &client
		}
	}
	if selected == nil {
		if query.Get("preview_client") != "" {
			preview.Error = "Choose an available OIDC client."
		}
		return preview, nil
	}
	if !oauthScope(preview.Scope) || !strings.Contains(" "+preview.Scope+" ", " openid ") {
		preview.Error = "Include openid and use only the supported scopes: profile, email, groups."
		return preview, nil
	}
	claims, err := a.oauthIdentityClaims(r.Context(), a.Q, *selected, user, preview.Scope)
	if err != nil {
		return preview, err
	}
	payload, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return preview, err
	}
	preview.JSON = string(payload)
	return preview, nil
}
