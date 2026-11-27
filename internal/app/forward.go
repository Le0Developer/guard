package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const forwardCallback = "/.guard/login"

func forwardPrefix(origin string) string {
	if strings.HasPrefix(origin, "https://") {
		return "__Host-"
	}
	return ""
}
func forwardCookie(client ids.ClientID, origin string) string {
	return fmt.Sprintf("%sguard_forwardauth_session_%d_%s", forwardPrefix(origin), client, security.Hash(origin)[:16])
}
func flowCookie(state, origin string) string {
	return forwardPrefix(origin) + "guard_forwardauth_flow_" + state
}
func validState(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
func forwardSetCookie(w http.ResponseWriter, origin, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(origin, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func forwardOriginal(r *http.Request) (string, string, error) {
	single := func(name string) (string, error) {
		v := r.Header.Values(name)
		if len(v) != 1 || v[0] == "" {
			return "", errors.New("missing or ambiguous proxy header")
		}
		return v[0], nil
	}
	proto, err := single("X-Forwarded-Proto")
	if err != nil || proto != "https" && proto != "http" {
		return "", "", errors.New("invalid forwarded protocol")
	}
	host, err := single("X-Forwarded-Host")
	if err != nil || strings.ContainsAny(host, "/,?#\\") {
		return "", "", errors.New("invalid forwarded host")
	}
	origin, err := security.Origin(proto + "://" + host)
	if err != nil {
		return "", "", err
	}
	uri := ""
	if r.URL.Path == forwardCallback {
		uri = r.URL.RequestURI()
	} else {
		uri, err = single("X-Forwarded-Uri")
		if err != nil {
			return "", "", err
		}
	}
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || len(uri) > 16384 {
		return "", "", errors.New("invalid forwarded URI")
	}
	u, err := security.URL(origin + uri)
	if err != nil {
		return "", "", err
	}
	actual, err := security.Origin(u.Scheme + "://" + u.Host)
	if err != nil || actual != origin {
		return "", "", errors.New("forwarded URI changed origin")
	}
	return origin, origin + uri, nil
}
func (a *App) forwardAllowed(ctx context.Context, q *db.Queries, c db.Client, origin string) (bool, error) {
	if c.ClientType != "ForwardAuth" || c.Disabled || c.DeletedAt != nil {
		return false, nil
	}
	redirects, err := q.ClientRedirectsByClientId(ctx, c.ID)
	if err != nil {
		return false, err
	}
	for _, d := range redirects {
		v, err := security.Origin(d.RedirectUri)
		if err == nil && v == origin {
			return true, nil
		}
	}
	return false, nil
}
func (a *App) forwardClient(ctx context.Context, origin string) (db.Client, error) {
	clients, err := a.Q.ListClients(ctx)
	if err != nil {
		return db.Client{}, err
	}
	var found *db.Client
	for _, c := range clients {
		allowed, err := a.forwardAllowed(ctx, a.Q, c, origin)
		if err != nil {
			return c, err
		}
		if allowed {
			if found != nil {
				return c, errors.New("ambiguous ForwardAuth origin")
			}
			copy := c
			found = &copy
		}
	}
	if found == nil {
		return db.Client{}, errors.New("no ForwardAuth client allows this origin")
	}
	return *found, nil
}
func (a *App) forwardStart(ctx context.Context, c db.Client, returnURI string) (string, string, string, error) {
	u, err := security.URL(returnURI)
	if err != nil {
		return "", "", "", err
	}
	origin, err := security.Origin(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", "", "", err
	}
	state, browser := security.Token(), security.Token()
	err = transaction(ctx, a.Pool, func(q *db.Queries) error {
		current, err := q.LockClient(ctx, c.ID)
		if err != nil {
			return err
		}
		allowed, err := a.forwardAllowed(ctx, q, current, origin)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("origin no longer registered")
		}
		_, err = q.CreateForwardAuthRequest(ctx, db.CreateForwardAuthRequestParams{StateHash: security.Hash(state), BrowserHash: security.Hash(browser), ClientID: c.ID, Origin: origin, ReturnUri: returnURI, ExpiresAt: time.Now().Add(5 * time.Minute)})
		return err
	})
	if err != nil {
		return "", "", "", err
	}
	query := url.Values{"client_id": {c.ClientID}, "client_type": {"forwardauth"}, "redirect_uri": {origin}, "response_type": {"code"}, "state": {state}}
	return state, browser, a.Config.Domain + "/oauth2/authorize?" + query.Encode(), nil
}
func (a *App) authorizeForward(w http.ResponseWriter, r *http.Request, c db.Client, fields url.Values) {
	state := fields.Get("state")
	origin, err := security.Origin(fields.Get("redirect_uri"))
	if err != nil || !validState(state) || fields.Get("client_type") != "forwardauth" || fields.Get("response_type") != "code" {
		a.fail(w, r, 400, "Invalid ForwardAuth authorization.")
		return
	}
	flow, err := a.Q.ForwardAuthRequestByStateHash(r.Context(), security.Hash(state))
	if err != nil || flow.ClientID != c.ID || flow.Origin != origin || flow.ConsumedAt != nil || !flow.ExpiresAt.After(time.Now()) {
		if err != nil && !notFound(err) {
			a.serverError(w, r, err)
		} else {
			a.fail(w, r, 400, "Expired or mismatched ForwardAuth request.")
		}
		return
	}
	v, ok := a.user(r)
	prompt := fields.Get("prompt")
	if prompt != "" && prompt != "none" && prompt != "login" {
		a.fail(w, r, 400, "Unsupported prompt.")
		return
	}
	force := prompt == "login"
	if age := fields.Get("max_age"); age != "" {
		n, e := time.ParseDuration(age + "s")
		if e != nil || n < 0 {
			a.fail(w, r, 400, "Invalid max_age.")
			return
		}
		force = force || ok && (v.Session.AuthTime <= 0 || n == 0 || time.Since(time.Unix(v.Session.AuthTime, 0)) > n)
	}
	if !ok || force {
		if prompt == "none" {
			jsonResponse(w, 400, map[string]string{"error": "login_required"})
			return
		}
		http.Redirect(w, r, oauthLoginRedirect(fields), 303)
		return
	}
	code := security.Token()
	err = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		current, err := q.LockClient(r.Context(), c.ID)
		if err != nil {
			return err
		}
		allowed, err := a.forwardAllowed(r.Context(), q, current, origin)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("origin no longer allowed")
		}
		f, err := q.LockForwardAuthRequest(r.Context(), flow.ID)
		if err != nil {
			return err
		}
		if f.ConsumedAt != nil || !f.ExpiresAt.After(time.Now()) || f.CodeHash != nil {
			return errors.New("ForwardAuth authorization already used")
		}
		session, err := a.sessionByID(r.Context(), q, v.Session.ID)
		if err != nil {
			return err
		}
		if session == nil || session.User.ID != v.User.ID {
			return errors.New("session expired")
		}
		allowed, err = a.permitted(r.Context(), q, c.ID, v.User.ID)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("access denied")
		}
		_, err = q.UpdateForwardAuthRequest(r.Context(), db.UpdateForwardAuthRequestParams{ID: f.ID, StateHash: f.StateHash, BrowserHash: f.BrowserHash, CodeHash: ptr(security.Hash(code)), ClientID: f.ClientID, Origin: f.Origin, ReturnUri: f.ReturnUri, UserID: &v.User.ID, SessionID: &v.Session.ID, ExpiresAt: f.ExpiresAt})
		if err != nil {
			return err
		}
		return a.audit(r.Context(), q, v.User.ID, "ForwardAuth authorized", map[string]any{"client_id": c.ID, "session_id": v.Session.ID})
	})
	if err != nil {
		a.fail(w, r, 403, "Unable to authorize this application.")
		return
	}
	http.Redirect(w, r, origin+forwardCallback+"?"+url.Values{"state": {state}, "code": {code}}.Encode(), 303)
}
func (a *App) forwardFinish(ctx context.Context, origin, state, code, browser string) (string, string, int, error) {
	if !validState(state) {
		return "", "", 0, errors.New("invalid state")
	}
	raw := security.Token()
	var redirect string
	var lifetime int
	err := transaction(ctx, a.Pool, func(q *db.Queries) error {
		// Lock ordering is client before request, matching authorization and administration.
		candidate, err := q.ForwardAuthRequestByStateHash(ctx, security.Hash(state))
		if err != nil {
			return err
		}
		c, err := q.LockClient(ctx, candidate.ClientID)
		if err != nil {
			return err
		}
		f, err := q.LockForwardAuthRequestByStateHash(ctx, security.Hash(state))
		if err != nil {
			return err
		}
		if f.ConsumedAt != nil || !f.ExpiresAt.After(time.Now()) || f.Origin != origin || f.CodeHash == nil || !security.Equal(*f.CodeHash, security.Hash(code)) || !security.Equal(f.BrowserHash, security.Hash(browser)) || f.UserID == nil || f.SessionID == nil {
			return errors.New("invalid or expired callback")
		}
		allowed, err := a.forwardAllowed(ctx, q, c, origin)
		if err != nil {
			return err
		}
		u, err := security.URL(f.ReturnUri)
		if err != nil {
			return err
		}
		actual, err := security.Origin(u.Scheme + "://" + u.Host)
		if err != nil || actual != origin || !allowed {
			return errors.New("origin no longer allowed")
		}
		v, err := a.sessionByID(ctx, q, *f.SessionID)
		if err != nil {
			return err
		}
		if v == nil || v.User.ID != *f.UserID {
			return errors.New("session expired")
		}
		allowed, err = a.permitted(ctx, q, c.ID, v.User.ID)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("access denied")
		}
		expires := time.Now().Add(time.Duration(c.SessionLifetimeS) * time.Second)
		if v.Session.ExpiresAt.Before(expires) {
			expires = v.Session.ExpiresAt
		}
		lifetime = int(time.Until(expires).Seconds())
		if lifetime < 1 {
			return errors.New("expired session")
		}
		_, err = q.CreateForwardAuthSession(ctx, db.CreateForwardAuthSessionParams{TokenHash: security.Hash(raw), ClientID: c.ID, UserID: v.User.ID, SessionID: v.Session.ID, Origin: origin, ExpiresAt: expires})
		if err != nil {
			return err
		}
		redirect = f.ReturnUri
		_, err = q.UpdateForwardAuthRequest(ctx, db.UpdateForwardAuthRequestParams{ID: f.ID, StateHash: f.StateHash, BrowserHash: f.BrowserHash, CodeHash: f.CodeHash, ClientID: f.ClientID, Origin: f.Origin, ReturnUri: "", UserID: f.UserID, SessionID: f.SessionID, ExpiresAt: f.ExpiresAt, ConsumedAt: ptr(time.Now())})
		if err != nil {
			return err
		}
		return a.audit(ctx, q, v.User.ID, "ForwardAuth session created", map[string]any{"client_id": c.ID, "session_id": v.Session.ID})
	})
	return raw, redirect, lifetime, err
}
func (a *App) ForwardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture := newBufferedResponse()
		a.forwardVerify(capture, r)
		if r.URL.Path == "/auth_request" && capture.status >= 300 && capture.status < 400 {
			capture.status = 401
			cookies := capture.Header().Values("Set-Cookie")
			capture.Header().Del("Set-Cookie")
			if len(cookies) > 0 {
				capture.Header().Set("Set-Cookie", cookies[0])
			}
		}
		capture.flush(w)
	})
}
func (a *App) forwardVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	origin, original, err := forwardOriginal(r)
	if err != nil {
		a.fail(w, r, 400, err.Error())
		return
	}
	u, _ := url.Parse(original)
	if u.Path == forwardCallback {
		fields, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			a.fail(w, r, 400, "Invalid callback query.")
			return
		}
		for _, v := range fields {
			if len(v) != 1 {
				a.fail(w, r, 400, "Repeated callback parameter.")
				return
			}
		}
		state := fields.Get("state")
		if !validState(state) {
			a.fail(w, r, 400, "Invalid callback state.")
			return
		}
		raw, redirect, lifetime, err := a.forwardFinish(r.Context(), origin, state, fields.Get("code"), cookieValue(r, flowCookie(state, origin)))
		if err != nil {
			a.fail(w, r, 400, "Invalid or expired ForwardAuth callback.")
			return
		}
		f, err := a.Q.ForwardAuthRequestByStateHash(r.Context(), security.Hash(state))
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		c, err := a.Q.GetClient(r.Context(), f.ClientID)
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		if err = a.recordAccess(r.Context(), c, f.UserID, f.SessionID, "forwardauth", map[string]any{"decision": "allowed", "path": forwardCallback, "origin": origin, "status": 303, "client_ip": a.requestIP(r)}); err != nil {
			journalUnavailable(w)
			return
		}
		forwardSetCookie(w, origin, forwardCookie(f.ClientID, origin), raw, lifetime)
		forwardSetCookie(w, origin, flowCookie(state, origin), "", -1)
		http.Redirect(w, r, redirect, 303)
		return
	}
	if r.URL.Path == forwardCallback {
		a.fail(w, r, 400, "The original callback URL is missing.")
		return
	}
	c, err := a.forwardClient(r.Context(), origin)
	if err != nil {
		a.fail(w, r, 403, "No unique ForwardAuth client allows this application.")
		return
	}
	raw := cookieValue(r, forwardCookie(c.ID, origin))
	if raw != "" {
		s, err := a.Q.ForwardAuthSessionByTokenHash(r.Context(), security.Hash(raw))
		if err != nil && !notFound(err) {
			a.serverError(w, r, err)
			return
		}
		if err == nil && s.ClientID == c.ID && s.Origin == origin && s.ExpiresAt.After(time.Now()) {
			v, err := a.sessionByID(r.Context(), a.Q, s.SessionID)
			if err != nil {
				a.serverError(w, r, err)
				return
			}
			if v != nil && v.User.ID == s.UserID {
				allowed, err := a.permitted(r.Context(), a.Q, c.ID, v.User.ID)
				if err != nil {
					a.serverError(w, r, err)
					return
				}
				if !allowed {
					if err := a.recordAccess(r.Context(), c, &v.User.ID, &s.SessionID, "forwardauth", map[string]any{"decision": "denied", "path": u.Path, "origin": origin, "status": 403, "client_ip": a.requestIP(r)}); err != nil {
						journalUnavailable(w)
						return
					}
					a.fail(w, r, 403, "Access denied.")
					return
				}
				w.Header().Set("X-Guard-User-Id", fmt.Sprint(v.User.ID))
				w.Header().Set("X-Guard-Username", v.User.Username)
				if err := a.recordAccess(r.Context(), c, &v.User.ID, &s.SessionID, "forwardauth", map[string]any{"decision": "allowed", "path": u.Path, "origin": origin, "status": 200, "client_ip": a.requestIP(r)}); err != nil {
					journalUnavailable(w)
					return
				}
				w.WriteHeader(200)
				return
			}
		}
	}
	state, browser, authorize, err := a.forwardStart(r.Context(), c, original)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	forwardSetCookie(w, origin, flowCookie(state, origin), browser, 300)
	if err := a.recordAccess(r.Context(), c, nil, nil, "forwardauth", map[string]any{"decision": "authentication_required", "path": u.Path, "origin": origin, "status": 303, "client_ip": a.requestIP(r)}); err != nil {
		journalUnavailable(w)
		return
	}
	if r.URL.Path == "/auth_request" {
		w.Header().Set("Location", authorize)
		w.WriteHeader(401)
	} else {
		http.Redirect(w, r, authorize, 303)
	}
}
