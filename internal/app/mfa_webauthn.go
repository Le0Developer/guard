package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type mfaWebUser struct {
	db.User
	Credentials []webauthn.Credential
}

func (u mfaWebUser) WebAuthnID() []byte                         { return u.WebauthnUserID }
func (u mfaWebUser) WebAuthnName() string                       { return u.Username }
func (u mfaWebUser) WebAuthnDisplayName() string                { return u.Username }
func (u mfaWebUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (a *App) mfaWeb() (*webauthn.WebAuthn, error) {
	u, e := url.Parse(a.Config.Domain)
	if e != nil {
		return nil, e
	}
	if u.Hostname() == "" || (u.Scheme != "https" && (u.Scheme != "http" || u.Hostname() != "localhost")) {
		return nil, errors.New("Security keys require HTTPS or http://localhost.")
	}
	return webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: a.Config.brandName(), RPOrigins: []string{u.Scheme + "://" + u.Host}})
}
func mfaWebLoad(ctx context.Context, q *db.Queries, u db.User) (mfaWebUser, error) {
	v := mfaWebUser{User: u}
	ks, e := q.WebauthnCredentialsByUserId(ctx, u.ID)
	if e != nil {
		return v, e
	}
	for _, k := range ks {
		var c webauthn.Credential
		if e = json.Unmarshal(k.Credential, &c); e != nil {
			return v, e
		}
		v.Credentials = append(v.Credentials, c)
	}
	return v, nil
}
func (a *App) mfaEnrollStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var result map[string]any
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, e := a.mfaContext(r, q)
		if e != nil {
			return e
		}
		name, e := mfaName(r.FormValue("name"))
		if e != nil {
			return e
		}
		wa, e := a.mfaWeb()
		if e != nil {
			return e
		}
		u, e := mfaWebLoad(ctx, q, c.Target)
		if e != nil {
			return e
		}
		options, session, e := wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.Credentials).CredentialDescriptors()))
		if e != nil {
			return e
		}
		state, e := json.Marshal(session)
		if e != nil {
			return e
		}
		ticket, e := a.mfaTicket(ctx, q, c.Target, c.Actor.ID, &c.Session.ID, nil, "key-enroll", mfaState{Name: name, Web: state})
		if e != nil {
			return e
		}
		result = map[string]any{"publicKey": options.Response, "ceremony": ticket}
		return nil
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	jsonResponse(w, 200, result)
}
func (a *App) mfaEnrollFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var base string
	rejected := false
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, e := a.mfaContext(r, q)
		if e != nil {
			return e
		}
		base = c.Base
		ticket, u, e := a.mfaLoad(ctx, q, r.FormValue("ceremony"), "key-enroll")
		if e != nil {
			return e
		}
		if !c.bound(ticket) {
			return errMFA
		}
		var state mfaState
		if e = json.Unmarshal(ticket.State, &state); e != nil {
			return e
		}
		var session webauthn.SessionData
		if e = json.Unmarshal(state.Web, &session); e != nil {
			return e
		}
		wa, e := a.mfaWeb()
		if e != nil {
			return e
		}
		wu, e := mfaWebLoad(ctx, q, u)
		if e != nil {
			return e
		}
		request, e := http.NewRequest("POST", a.Config.Domain, strings.NewReader(r.FormValue("credential")))
		if e != nil {
			return e
		}
		if e = q.MFAConsume(ctx, ticket.ID); e != nil {
			return e
		}
		credential, e := wa.FinishRegistration(wu, session, request)
		if e != nil {
			rejected = true
			return a.mfaFailure(ctx, q, ticket, u)
		}
		b, e := json.Marshal(credential)
		if e != nil {
			return e
		}
		_, e = q.CreateWebauthnCredential(ctx, db.CreateWebauthnCredentialParams{UserID: u.ID, CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID), Name: state.Name, Credential: b, SignCount: int64(credential.Authenticator.SignCount)})
		if e != nil {
			return e
		}
		return a.mfaChanged(ctx, q, u, c.Actor.ID, c.keep(), "Added security key")
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	if rejected {
		a.mfaError(w, r, errors.New("Invalid security key response."))
		return
	}
	jsonResponse(w, 200, map[string]string{"redirect": base})
}
func (a *App) mfaAuthStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var result map[string]any
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		pending, u, e := a.mfaLoad(ctx, q, mfaPending(r), "login")
		if e != nil {
			return e
		}
		if e = a.mfaLoginBound(ctx, q, r, pending); e != nil {
			return e
		}
		wa, e := a.mfaWeb()
		if e != nil {
			return e
		}
		wu, e := mfaWebLoad(ctx, q, u)
		if e != nil {
			return e
		}
		options, session, e := wa.BeginLogin(wu)
		if e != nil {
			return e
		}
		state, e := json.Marshal(session)
		if e != nil {
			return e
		}
		ticket, e := a.mfaTicket(ctx, q, u, u.ID, nil, pending.LoginSessionID, "key-login", mfaState{Pending: mfaHash(mfaPending(r)), Web: state})
		if e != nil {
			return e
		}
		result = map[string]any{"publicKey": options.Response, "ceremony": ticket}
		return nil
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	jsonResponse(w, 200, result)
}
func (a *App) mfaAuthFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var u db.User
	var login db.LoginSession
	rejected := false
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		pending, v, e := a.mfaLoad(ctx, q, mfaPending(r), "login")
		if e != nil {
			return e
		}
		u = v
		if e = a.mfaLoginBound(ctx, q, r, pending); e != nil {
			return e
		}
		ticket, _, e := a.mfaLoad(ctx, q, r.FormValue("ceremony"), "key-login")
		if e != nil {
			return e
		}
		var state mfaState
		if e = json.Unmarshal(ticket.State, &state); e != nil {
			return e
		}
		if state.Pending != mfaHash(mfaPending(r)) || ticket.UserID != u.ID || pending.LoginSessionID == nil || ticket.LoginSessionID == nil || *ticket.LoginSessionID != *pending.LoginSessionID {
			return errMFA
		}
		login, e = q.LockLoginSession(ctx, *pending.LoginSessionID)
		if e != nil {
			return e
		}
		var session webauthn.SessionData
		if e = json.Unmarshal(state.Web, &session); e != nil {
			return e
		}
		wa, e := a.mfaWeb()
		if e != nil {
			return e
		}
		wu, e := mfaWebLoad(ctx, q, u)
		if e != nil {
			return e
		}
		request, e := http.NewRequest("POST", a.Config.Domain, strings.NewReader(r.FormValue("credential")))
		if e != nil {
			return e
		}
		if e = q.MFAConsume(ctx, ticket.ID); e != nil {
			return e
		}
		credential, e := wa.FinishLogin(wu, session, request)
		if e != nil || credential.Authenticator.CloneWarning {
			rejected = true
			return a.mfaFailure(ctx, q, pending, u)
		}
		key, e := q.LockWebauthnCredentialByCredentialId(ctx, base64.RawURLEncoding.EncodeToString(credential.ID))
		if e != nil {
			return e
		}
		if key.UserID != u.ID {
			return errMFA
		}
		b, e := json.Marshal(credential)
		if e != nil {
			return e
		}
		_, e = q.UpdateWebauthnCredential(ctx, db.UpdateWebauthnCredentialParams{ID: key.ID, UserID: u.ID, CredentialID: key.CredentialID, Name: key.Name, Credential: b, SignCount: int64(credential.Authenticator.SignCount), LastUsedAt: ptr(time.Now())})
		if e != nil {
			return e
		}
		if e = q.MFAConsume(ctx, ticket.ID); e != nil {
			return e
		}
		if e = q.MFAConsume(ctx, pending.ID); e != nil {
			return e
		}
		return q.MFAResetFailures(ctx, u.ID)
	})
	if e != nil {
		a.mfaError(w, r, e)
		return
	}
	if rejected {
		a.mfaError(w, r, errors.New("Invalid security key response."))
		return
	}
	rec := newBufferedResponse()
	if e = a.finishLogin(rec, r, u, login); e != nil {
		a.serverError(w, r, e)
		return
	}
	for _, v := range rec.Header().Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", v)
	}
	a.mfaCookie(w, "mfa_pending", "", -1)
	jsonResponse(w, 200, map[string]string{"redirect": security.SafeRedirect(login.RedirectUri)})
}
func (a *App) mfaLoginBound(ctx context.Context, q *db.Queries, r *http.Request, t db.MfaCeremony) error {
	if t.LoginSessionID == nil {
		return errMFA
	}
	cookie, e := r.Cookie("login_session")
	if e != nil {
		return errMFA
	}
	login, e := q.GetLoginSession(ctx, *t.LoginSessionID)
	if e != nil {
		return e
	}
	if login.TokenHash != mfaHash(cookie.Value) || !login.ExpiresAt.After(time.Now()) {
		return errMFA
	}
	return nil
}
