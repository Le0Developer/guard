package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var errMFARecent = errors.New("Sign in again before changing security settings.")
var errMFAForbidden = errors.New("You cannot manage another account security.")
var errMFA = errors.New("This security request has expired or is invalid. Start again.")

type mfaState struct {
	Name    string          `json:"name,omitempty"`
	Secret  string          `json:"secret,omitempty"`
	Pending string          `json:"pending,omitempty"`
	Web     json.RawMessage `json:"web,omitempty"`
}

func mfaName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > 100 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", errors.New("Enter a name of 1–100 characters.")
	}
	return s, nil
}
func (a *App) mfaTicket(ctx context.Context, q *db.Queries, u db.User, actor ids.UserID, session *ids.SessionID, login *ids.LoginSessionID, purpose string, state mfaState) (string, error) {
	s, e := json.Marshal(state)
	if e != nil {
		return "", e
	}
	raw := mfaRandom()
	_, e = q.CreateMfaCeremony(ctx, db.CreateMfaCeremonyParams{TokenHash: mfaHash(raw), UserID: u.ID, ActorID: actor, SessionID: session, LoginSessionID: login, Revision: u.MfaRevision, Purpose: purpose, State: s, ExpiresAt: time.Now().Add(5 * time.Minute)})
	return raw, e
}
func (a *App) mfaLoad(ctx context.Context, q *db.Queries, raw, purpose string) (db.MfaCeremony, db.User, error) {
	c, e := q.MfaCeremonyByTokenHash(ctx, mfaHash(raw))
	if e != nil {
		return c, db.User{}, e
	}
	u, e := q.LockUser(ctx, c.UserID)
	if e != nil {
		return c, u, e
	}
	c, e = q.LockMfaCeremony(ctx, c.ID)
	if e != nil {
		return c, u, e
	}
	if c.Purpose != purpose || c.ConsumedAt != nil || c.Attempts >= 5 || !c.ExpiresAt.After(time.Now()) || c.Revision != u.MfaRevision || u.Disabled || u.DeletedAt != nil {
		return c, u, errMFA
	}
	if u.MfaFailures >= 5 && u.MfaWindow != nil && u.MfaWindow.Add(5*time.Minute).After(time.Now()) {
		return c, u, errors.New("Too many attempts. Wait five minutes.")
	}
	return c, u, nil
}
func (a *App) mfaChanged(ctx context.Context, q *db.Queries, u db.User, actor ids.UserID, keep ids.SessionID, action string) error {
	if e := q.MFABumpRevision(ctx, u.ID); e != nil {
		return e
	}
	if e := q.MFADeleteCeremonies(ctx, u.ID); e != nil {
		return e
	}
	if e := q.MFARevokeSessions(ctx, db.MFARevokeSessionsParams{UserID: u.ID, KeepSession: keep}); e != nil {
		return e
	}
	return a.audit(ctx, q, actor, "MFA security changed", map[string]any{"subject_id": u.ID, "action": action})
}
func (a *App) startMFA(w http.ResponseWriter, r *http.Request, u db.User, login db.LoginSession) error {
	var raw string
	e := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		current, e := q.LockUser(r.Context(), u.ID)
		if e != nil {
			return e
		}
		if current.Disabled || current.DeletedAt != nil || current.Password != u.Password || current.Email != u.Email {
			return errMFA
		}
		l, e := q.LockLoginSession(r.Context(), login.ID)
		if e != nil {
			return e
		}
		if !l.ExpiresAt.After(time.Now()) {
			return errMFA
		}
		raw, e = a.mfaTicket(r.Context(), q, current, u.ID, nil, &login.ID, "login", mfaState{})
		return e
	})
	if e != nil {
		return e
	}
	a.mfaCookie(w, "mfa_pending", raw, 300)
	http.Redirect(w, r, "/login/mfa", 303)
	return nil
}
func (a *App) mfaCookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.Domain, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func mfaPending(r *http.Request) string {
	c, e := r.Cookie("mfa_pending")
	if e != nil {
		return ""
	}
	return c.Value
}
func (a *App) registerMFA(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/mfa", a.mfaChallenge)
	mux.HandleFunc("POST /login/mfa", a.mfaCode)
	mux.HandleFunc("POST /login/mfa/key/start", a.mfaAuthStart)
	mux.HandleFunc("POST /login/mfa/key/finish", a.mfaAuthFinish)
	for _, base := range []string{"/security", "/account/security", "/admin/users/{id}/security"} {
		mux.HandleFunc("GET "+base, a.mfaManagePage)
		for _, route := range []string{"/totp", "/totp/confirm", "/keys/start", "/keys/finish", "/backup-codes", "/reset", "/methods/{kind}/{method_id}/remove", "/methods/{kind}/{method_id}/rename"} {
			mux.HandleFunc("POST "+base+route, a.mfaManage)
		}
	}
}
func (a *App) mfaError(w http.ResponseWriter, r *http.Request, e error) {
	if errors.Is(e, errMFARecent) {
		if strings.Contains(r.URL.Path, "/keys/") {
			jsonResponse(w, 401, map[string]string{"error": e.Error()})
			return
		}
		base := "/security"
		if id := r.PathValue("id"); id != "" {
			base = "/admin/users/" + url.PathEscape(id) + "/security"
		} else if r.URL.Path == "/account/security" || strings.HasPrefix(r.URL.Path, "/account/security/") {
			base = "/account/security"
		}
		http.Redirect(w, r, "/login?r="+url.QueryEscape(base), 303)
		return
	}
	if errors.Is(e, errMFAForbidden) {
		jsonResponse(w, 403, map[string]string{"error": e.Error()})
		return
	}
	var pe *pgconn.PgError
	if errors.As(e, &pe) {
		a.serverError(w, r, e)
		return
	}
	if notFound(e) {
		e = errMFA
	}
	jsonResponse(w, 400, map[string]string{"error": e.Error()})
}
func (a *App) mfaChallenge(w http.ResponseWriter, r *http.Request) {
	hasTOTP, hasKeys := false, false
	e := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		ticket, user, e := a.mfaLoad(r.Context(), q, mfaPending(r), "login")
		if e != nil {
			return e
		}
		if e = a.mfaLoginBound(r.Context(), q, r, ticket); e != nil {
			return e
		}
		factors, e := q.TotpAuthenticatorsByUserId(r.Context(), user.ID)
		if e != nil {
			return e
		}
		keys, e := q.WebauthnCredentialsByUserId(r.Context(), user.ID)
		if e != nil {
			return e
		}
		hasTOTP, hasKeys = len(factors) > 0, len(keys) > 0
		return nil
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	a.page(w, r, "Verify sign-in", mfaChallengeTemplate, map[string]any{"HasTOTP": hasTOTP, "HasKeys": hasKeys})
}
func (a *App) mfaFailure(ctx context.Context, q *db.Queries, c db.MfaCeremony, u db.User) error {
	if e := q.MFAAttempt(ctx, c.ID); e != nil {
		return e
	}
	if e := q.MFAFailure(ctx, u.ID); e != nil {
		return e
	}
	return a.audit(ctx, q, u.ID, "MFA verification rejected", map[string]any{"purpose": c.Purpose})
}
func (a *App) mfaCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var u db.User
	var login db.LoginSession
	accepted := false
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, v, e := a.mfaLoad(ctx, q, mfaPending(r), "login")
		if e != nil {
			return e
		}
		u = v
		if e = a.mfaLoginBound(ctx, q, r, c); e != nil {
			return e
		}
		if c.LoginSessionID == nil {
			return errMFA
		}
		login, e = q.LockLoginSession(ctx, *c.LoginSessionID)
		if e != nil {
			return e
		}
		if !login.ExpiresAt.After(time.Now()) {
			return errMFA
		}
		code := strings.TrimSpace(r.FormValue("code"))
		if r.FormValue("method") == "recovery" || r.FormValue("method") == "backup" {
			rc, e := q.LockRecoveryCodeByHash(ctx, mfaRecoveryHash(u.ID, code))
			if e == nil && rc.UserID == u.ID && rc.UsedAt == nil {
				_, e = q.UpdateRecoveryCode(ctx, db.UpdateRecoveryCodeParams{ID: rc.ID, UserID: u.ID, Hash: rc.Hash, UsedAt: ptr(time.Now())})
				if e != nil {
					return e
				}
				accepted = true
			} else if e != nil && !notFound(e) {
				return e
			}
		} else {
			factors, e := q.TotpAuthenticatorsByUserId(ctx, u.ID)
			if e != nil {
				return e
			}
			for _, f := range factors {
				secret, e := a.mfaOpen(u.ID, f.Secret)
				if e != nil {
					return e
				}
				if step, ok := mfaStep(secret, code, f.LastStep); ok {
					_, e = q.UpdateTotpAuthenticator(ctx, db.UpdateTotpAuthenticatorParams{ID: f.ID, UserID: u.ID, Name: f.Name, Secret: f.Secret, LastStep: step, LastUsedAt: ptr(time.Now())})
					if e != nil {
						return e
					}
					accepted = true
					break
				}
			}
		}
		if !accepted {
			return a.mfaFailure(ctx, q, c, u)
		}
		if e = q.MFAConsume(ctx, c.ID); e != nil {
			return e
		}
		return q.MFAResetFailures(ctx, u.ID)
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	if !accepted {
		a.mfaError(w, r, errors.New("Invalid or already used code."))
		return
	}
	a.mfaCookie(w, "mfa_pending", "", -1)
	if e = a.finishLogin(w, r, u, login); e != nil {
		a.serverError(w, r, e)
	}
}

type mfaContext struct {
	Actor   db.User
	Target  db.User
	Session db.Session
	Base    string
}

func (a *App) mfaContext(r *http.Request, q *db.Queries) (mfaContext, error) {
	var c mfaContext
	v, ok := a.user(r)
	if !ok {
		return c, errMFARecent
	}
	targetID := v.User.ID
	if r.PathValue("id") != "" {
		n, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil || n < 0 {
			return c, errMFA
		}
		targetID = ids.UserID(n)
	}
	// Lock account rows in numeric order before session rows, matching revocation's
	// account-before-session order and avoiding cross-administrator deadlocks.
	first, second := v.User.ID, targetID
	if second < first {
		first, second = second, first
	}
	if _, e := q.LockUser(r.Context(), first); e != nil {
		return c, e
	}
	if second != first {
		if _, e := q.LockUser(r.Context(), second); e != nil {
			return c, e
		}
	}
	session, e := q.LockSession(r.Context(), v.Session.ID)
	if e != nil {
		return c, errMFARecent
	}
	actor, e := q.GetUser(r.Context(), v.User.ID)
	if e != nil {
		return c, e
	}
	if actor.Disabled || actor.DeletedAt != nil || session.UserID != actor.ID || !session.ExpiresAt.After(time.Now()) || session.CreatedAt.Add(5*time.Minute).Before(time.Now()) {
		return c, errMFARecent
	}
	if targetID != actor.ID && actor.Role != "Admin" {
		return c, errMFAForbidden
	}
	target, e := q.GetUser(r.Context(), targetID)
	if e != nil {
		return c, e
	}
	if target.DeletedAt != nil {
		return c, errMFA
	}
	base := "/security"
	if targetID != actor.ID {
		base = fmt.Sprintf("/admin/users/%d/security", targetID)
	}
	return mfaContext{actor, target, session, base}, nil
}
func (c mfaContext) bound(t db.MfaCeremony) bool {
	return t.UserID == c.Target.ID && t.ActorID == c.Actor.ID && t.SessionID != nil && *t.SessionID == c.Session.ID
}
func (c mfaContext) keep() ids.SessionID {
	if c.Actor.ID == c.Target.ID {
		return c.Session.ID
	}
	return 0
}
func (a *App) mfaManagePage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireUser(w, r); !ok {
		return
	}
	var c mfaContext
	var methods []map[string]any
	count := 0
	e := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		var e error
		c, e = a.mfaContext(r, q)
		if e != nil {
			return e
		}
		fs, e := q.TotpAuthenticatorsByUserId(r.Context(), c.Target.ID)
		if e != nil {
			return e
		}
		for _, f := range fs {
			methods = append(methods, map[string]any{"ID": f.ID, "Kind": "totp", "Name": f.Name, "CreatedAt": f.CreatedAt, "LastUsed": f.LastUsedAt})
		}
		ks, e := q.WebauthnCredentialsByUserId(r.Context(), c.Target.ID)
		if e != nil {
			return e
		}
		for _, k := range ks {
			methods = append(methods, map[string]any{"ID": k.ID, "Kind": "webauthn", "Name": k.Name, "CreatedAt": k.CreatedAt, "LastUsed": k.LastUsedAt})
		}
		rs, e := q.RecoveryCodesByUserId(r.Context(), c.Target.ID)
		for _, v := range rs {
			if v.UsedAt == nil {
				count++
			}
		}
		return e
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	a.page(w, r, "Security · "+c.Target.Username, mfaManagementTemplate, map[string]any{"Base": c.Base, "Methods": methods, "Count": count, "Name": c.Target.Username, "Back": fmt.Sprintf("/admin/users/%d", c.Target.ID)})
}
