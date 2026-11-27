package app

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"mime"
	"net/http"
	"strings"
	"time"
)

var errUpstreamSessionChanged = errors.New("upstream sign-in is no longer valid")

type upstreamLoginState struct {
	Exchanged  bool                   `json:"exchanged"`
	Nonce      string                 `json:"nonce"`
	ProviderID ids.UpstreamProviderID `json:"provider_id"`
	Revision   int64                  `json:"revision"`
}

func (a *App) provider(ctx context.Context, slug string) (db.UpstreamProvider, error) {
	p, err := a.Q.UpstreamProviderBySlug(ctx, slug)
	if err == nil && (!p.Enabled || p.DeletedAt != nil) {
		err = pgx.ErrNoRows
	}
	return p, err
}
func isUpstreamLogoutPath(path string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 4 && parts[1] == "login" && parts[2] != "" && parts[3] == "backchannel-logout"
}
func checkUpstreamBinding(ctx context.Context, q *db.Queries, p db.UpstreamProvider, b db.UpstreamPendingLogin) error {
	if !p.Enabled || p.DeletedAt != nil || p.Revision != b.ProviderRevision {
		return errUpstreamSessionChanged
	}
	ended, err := q.HasUpstreamLogout(ctx, db.HasUpstreamLogoutParams{ProviderID: p.ID, ProviderRevision: p.Revision, TokenIssuedAt: b.TokenIssuedAt, Subject: b.Subject, Sid: b.Sid})
	if err != nil {
		return err
	}
	if ended {
		return errUpstreamSessionChanged
	}
	return nil
}

// Lock the provider before user/login rows, consistently with configuration and
// back-channel logout. Keep the lock through session creation to prevent revival.
func lockUpstreamPending(ctx context.Context, q *db.Queries, login db.LoginSession) (*db.UpstreamPendingLogin, error) {
	b, err := q.GetUpstreamPendingLogin(ctx, login.ID)
	if notFound(err) {
		if login.Provider != "" && login.Provider != "password" {
			return nil, errUpstreamSessionChanged
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := q.LockUpstreamProvider(ctx, b.ProviderID)
	if err != nil {
		return nil, err
	}
	if err = checkUpstreamBinding(ctx, q, p, b); err != nil {
		return nil, err
	}
	return &b, nil
}
func (a *App) saveUpstreamBinding(ctx context.Context, p db.UpstreamProvider, user db.User, login db.LoginSession, c upstreamClaims) error {
	return transaction(ctx, a.Pool, func(q *db.Queries) error {
		current, err := q.LockUpstreamProvider(ctx, p.ID)
		if err != nil {
			return err
		}
		b := db.UpstreamPendingLogin{LoginSessionID: login.ID, ProviderID: p.ID, UserID: user.ID, MatchedEmail: user.Email, Subject: c.Subject, Sid: c.SessionID, ProviderRevision: p.Revision, TokenIssuedAt: c.IssuedAt}
		if err = checkUpstreamBinding(ctx, q, current, b); err != nil {
			return err
		}
		locked, err := q.LockLoginSession(ctx, login.ID)
		if err != nil {
			return err
		}
		if !locked.ExpiresAt.After(time.Now()) {
			return errUpstreamSessionChanged
		}
		if err = q.BindUpstreamPendingLogin(ctx, db.BindUpstreamPendingLoginParams{LoginSessionID: login.ID, ProviderID: p.ID, UserID: user.ID, MatchedEmail: user.Email, Subject: c.Subject, Sid: c.SessionID, ProviderRevision: p.Revision, TokenIssuedAt: c.IssuedAt}); err != nil {
			return err
		}
		return nil
	})
}
func (a *App) upstreamBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, err := a.provider(r.Context(), r.PathValue("method"))
	if err != nil {
		if notFound(err) {
			a.fail(w, r, 404, "Unknown upstream provider.")
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	if p.ConfigurationMode == "oauth2" || !p.BackchannelLogoutEnabled {
		a.fail(w, r, 400, "Upstream logout is disabled.")
		return
	}
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/x-www-form-urlencoded" {
		oauthError(w, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if r.URL.RawQuery != "" || r.ParseForm() != nil || !oauthUnique(r.PostForm) || r.PostForm.Get("logout_token") == "" {
		oauthError(w, "invalid_request")
		return
	}
	claims, err := a.verifyUpstreamJWT(r.Context(), p, r.PostForm.Get("logout_token"), upstreamLogoutToken, "")
	if err != nil {
		if errors.Is(err, errUpstreamJWKSUnavailable) {
			jsonResponse(w, 503, map[string]string{"error": "temporarily_unavailable"})
		} else {
			oauthError(w, "invalid_request")
		}
		return
	}
	err = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		current, err := q.LockUpstreamProvider(r.Context(), p.ID)
		if err != nil {
			return err
		}
		if current.Revision != p.Revision || !current.Enabled || current.DeletedAt != nil || !current.BackchannelLogoutEnabled {
			return errUpstreamSessionChanged
		}
		retain := time.Now().Add(15 * time.Minute)
		expires := time.Unix(claims.ExpiresAt, 0)
		if expires.After(retain) {
			retain = expires
		}
		_, err = q.RecordUpstreamLogout(r.Context(), db.RecordUpstreamLogoutParams{ProviderID: p.ID, ProviderRevision: p.Revision, Jti: claims.JWTID, Subject: claims.Subject, Sid: claims.SessionID, IssuedAt: claims.IssuedAt, ExpiresAt: expires, RetainUntil: retain})
		if notFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		subjects, err := q.UpstreamLogoutSessionSubjects(r.Context(), db.UpstreamLogoutSessionSubjectsParams{ProviderID: p.ID, ProviderRevision: p.Revision, IssuedAt: claims.IssuedAt, Sid: claims.SessionID, Subject: claims.Subject})
		if err != nil {
			return err
		}
		if err = q.DeleteUpstreamLogoutPending(r.Context(), db.DeleteUpstreamLogoutPendingParams{ProviderID: p.ID, ProviderRevision: p.Revision, IssuedAt: claims.IssuedAt, Sid: claims.SessionID, Subject: claims.Subject}); err != nil {
			return err
		}
		if err = q.DeleteUpstreamLogoutSessions(r.Context(), db.DeleteUpstreamLogoutSessionsParams{ProviderID: p.ID, ProviderRevision: p.Revision, IssuedAt: claims.IssuedAt, Sid: claims.SessionID, Subject: claims.Subject}); err != nil {
			return err
		}
		for _, s := range subjects {
			if err = a.audit(r.Context(), q, s.UserID, "UpstreamLoggedOut", map[string]any{"provider_id": p.ID, "session_id": s.ID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errUpstreamSessionChanged) {
			oauthError(w, "invalid_request")
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	w.WriteHeader(200)
}
