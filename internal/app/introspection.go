package app

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
)

// registerIntrospection exposes backend-only, confidential-client token validation.
func (a *App) registerIntrospection(mux *http.ServeMux) {
	mux.HandleFunc("POST /oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		trace := &oauthTrace{}
		r = r.WithContext(context.WithValue(r.Context(), oauthTraceKey{}, trace))
		capture := newBufferedResponse()
		capture.Header().Set("Pragma", "no-cache")
		capture.Header().Set("Cache-Control", "no-store")
		a.oauthIntrospect(capture, r)
		if trace.client.ID != 0 {
			status := capture.status
			if status == 0 {
				status = 200
			}
			decision := "allowed"
			if status >= 500 {
				decision = "error"
			} else if status >= 400 {
				decision = "denied"
			}
			if err := a.recordAccess(r.Context(), trace.client, trace.user, trace.session, "oauth2", map[string]any{"decision": decision, "path": r.URL.Path, "status": status, "method": r.Method, "client_ip": a.requestIP(r)}); err != nil {
				journalUnavailable(capture)
			}
		}
		capture.flush(w)
	})
}

func (a *App) oauthIntrospect(w http.ResponseWriter, r *http.Request) {
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/x-www-form-urlencoded" {
		oauthError(w, "invalid_request")
		return
	}
	f, ok := oauthForm(w, r)
	if !ok {
		return
	}
	if f.Get("token") == "" || len(f.Get("token")) > 512 {
		oauthError(w, "invalid_request")
		return
	}
	out := map[string]any{"active": false}
	protocol := ""
	ctx := r.Context()
	err = transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, e := a.oauthAuthenticate(ctx, q, r, f)
		oauthSubject(r, c, nil, nil)
		if notFound(e) || errors.Is(e, oauthInvalid) {
			protocol = "invalid_client"
			return nil
		}
		if e != nil {
			return e
		}
		hash := security.Hash(f.Get("token"))
		token, e := q.OAuthTokenByAccessTokenHash(ctx, hash)
		access := true
		if notFound(e) {
			access = false
			token, e = q.OAuthTokenByRefreshTokenHash(ctx, hash)
		}
		if notFound(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if token.ClientID != c.ID {
			return nil
		}
		oauthSubject(r, c, &token.UserID, &token.SessionID)
		now := time.Now()
		if token.RevokedAt != nil || !token.ExpiresAt.After(now) || access && !token.AccessExpiresAt.After(now) {
			return nil
		}
		v, e := a.oauthGrantIdentity(ctx, q, c, token.UserID, token.SessionID)
		if errors.Is(e, oauthInvalid) {
			return nil
		}
		if e != nil {
			return e
		}
		expiry := token.ExpiresAt
		if access && token.AccessExpiresAt.Before(expiry) {
			expiry = token.AccessExpiresAt
		}
		out = map[string]any{"active": true, "client_id": c.ClientID, "sub": fmt.Sprint(v.User.ID), "username": v.User.Username, "scope": token.Scope, "exp": expiry.Unix(), "iat": token.CreatedAt.Unix(), "iss": a.oauthIssuer(c)}
		if access {
			out["token_type"] = "Bearer"
		}
		return nil
	})
	if err != nil {
		a.oauthServerError(w, r, err)
		return
	}
	if protocol != "" {
		oauthError(w, protocol)
		return
	}
	jsonResponse(w, 200, out)
}
