package app

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
)

func passwordResetURL(redirect string) string {
	return "/password-reset?r=" + queryEscape(security.SafeRedirect(redirect))
}

func passwordResetAllowedPath(path string) bool {
	return path == "/password-reset" || path == "/logout" || path == "/branding/icon" || strings.HasPrefix(path, "/static/")
}

// A completed primary authentication and MFA establish a browser session, but
// middleware and sessionByID restrict it until this password change commits.
func (a *App) passwordReset(w http.ResponseWriter, r *http.Request) {
	v, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	redirect := security.SafeRedirect(r.URL.Query().Get("r"))
	if strings.HasPrefix(redirect, "/password-reset") {
		redirect = "/"
	}
	if !v.User.ForcePasswordReset {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	render := func(message string) {
		a.page(w, r, "Change password", passwordResetTemplate, map[string]any{"Error": message})
	}
	if r.Method == http.MethodGet {
		render("")
		return
	}
	password := r.PostForm.Get("password")
	message := ""
	switch {
	case len(r.PostForm["password"]) != 1 || len(r.PostForm["confirm_password"]) != 1:
		message = "Invalid password fields."
	case len(password) < 8 || len(password) > 72:
		message = "Passwords must be between 8 and 72 bytes."
	case password != r.PostForm.Get("confirm_password"):
		message = "The passwords do not match."
	case v.User.Password != "" && security.VerifyPassword(password, v.User.Password):
		message = "Choose a password different from your current password."
	}
	if message != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		render(message)
		return
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	raw := security.Token()
	err = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		user, err := q.LockUser(r.Context(), v.User.ID)
		if err != nil {
			return err
		}
		if user.Disabled || user.DeletedAt != nil || !user.ForcePasswordReset || user.Password != v.User.Password || user.MfaRevision != v.User.MfaRevision {
			return errors.New("account changed during password reset")
		}
		session, err := q.LockSession(r.Context(), v.Session.ID)
		if err != nil {
			return err
		}
		if session.UserID != user.ID || !session.ExpiresAt.After(time.Now()) || !security.Equal(session.TokenHash, security.Hash(cookieValue(r, "session"))) {
			return errors.New("session expired during password reset")
		}
		params := adminUserParams(user)
		params.Password = hash
		params.ForcePasswordReset = false
		if _, err = q.UpdateUser(r.Context(), params); err != nil {
			return err
		}
		if err = q.AdminInvalidateUserLogins(r.Context(), user.ID); err != nil {
			return err
		}
		if err = q.AdminDeleteUserCeremonies(r.Context(), user.ID); err != nil {
			return err
		}
		if err = q.DeleteOtherUserSessions(r.Context(), db.DeleteOtherUserSessionsParams{UserID: user.ID, ID: session.ID}); err != nil {
			return err
		}
		if _, err = q.UpdateSession(r.Context(), db.UpdateSessionParams{ID: session.ID, UserID: user.ID, TokenHash: security.Hash(raw), ExpiresAt: session.ExpiresAt}); err != nil {
			return err
		}
		return a.audit(r.Context(), q, user.ID, "PasswordChanged", map[string]any{"forced": true})
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.setCookie(w, "session", raw, int(time.Until(v.Session.ExpiresAt).Seconds()))
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
