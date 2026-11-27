package app

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var oauthInvalid = errors.New("invalid_grant")

type oauthTraceKey struct{}
type oauthTrace struct {
	client  db.Client
	user    *ids.UserID
	session *ids.SessionID
}

func oauthSubject(r *http.Request, c db.Client, u *ids.UserID, s *ids.SessionID) {
	if t, ok := r.Context().Value(oauthTraceKey{}).(*oauthTrace); ok {
		t.client = c
		t.user = u
		t.session = s
	}
}

func oauthUnique(v url.Values) bool {
	for _, x := range v {
		if len(x) != 1 {
			return false
		}
	}
	return true
}
func oauthVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range []byte(v) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c))) {
			return false
		}
	}
	return true
}
func oauthPKCE(v, c, m string) bool {
	if !oauthVerifier(v) {
		return false
	}
	if m == "S256" {
		v = security.Hash(v)
	} else if m != "plain" {
		return false
	}
	return security.Equal(v, c)
}
func (a *App) oauthServerError(w http.ResponseWriter, r *http.Request, e error) {
	slog.Error("OAuth request failed", "path", r.URL.Path, "error", e)
	oauthError(w, "server_error")
}
func oauthError(w http.ResponseWriter, code string) {
	status := 400
	if code == "invalid_client" || code == "invalid_token" {
		status = 401
		scheme := "Bearer"
		if code == "invalid_client" {
			scheme = "Basic"
		}
		w.Header().Set("WWW-Authenticate", scheme+` realm="Guard"`)
	}
	if code == "server_error" {
		status = 503
	}
	jsonResponse(w, status, map[string]string{"error": code})
}
func (a *App) registerOAuth(mux *http.ServeMux) {
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			trace := &oauthTrace{}
			r = r.WithContext(context.WithValue(r.Context(), oauthTraceKey{}, trace))
			capture := newBufferedResponse()
			capture.Header().Set("Access-Control-Allow-Origin", "*")
			capture.Header().Set("Pragma", "no-cache")
			capture.Header().Set("Cache-Control", "no-store")
			h(capture, r)
			if trace.client.ID != 0 {
				decision := "allowed"
				status := capture.status
				if status == 0 {
					status = 200
				}
				if status >= 500 {
					decision = "error"
				} else if status >= 400 {
					decision = "denied"
				} else if status == 303 {
					u, e := url.Parse(capture.Header().Get("Location"))
					if e == nil {
						if u.Path == "/login" {
							decision = "authentication_required"
						} else if u.Query().Get("error") != "" {
							decision = "denied"
							if u.Query().Get("error") == "login_required" {
								decision = "authentication_required"
							}
						}
					}
				}
				if err := a.recordAccess(r.Context(), trace.client, trace.user, trace.session, "oauth2", map[string]any{"decision": decision, "path": r.URL.Path, "status": status, "method": r.Method, "client_ip": a.requestIP(r)}); err != nil {
					journalUnavailable(capture)
				}
			}
			capture.flush(w)
		}
	}
	mux.HandleFunc("GET /oauth2/{slug}/.well-known/openid-configuration", wrap(a.oauthDiscovery))
	mux.HandleFunc("GET /oauth2/{slug}/jwks", wrap(a.oauthJWKS))
	mux.HandleFunc("GET /oauth2/authorize", wrap(a.oauthAuthorize))
	mux.HandleFunc("POST /oauth2/token", wrap(a.oauthToken))
	mux.HandleFunc("GET /oauth2/userinfo", wrap(a.oauthUserinfo))
	mux.HandleFunc("POST /oauth2/userinfo", wrap(a.oauthUserinfo))
	mux.HandleFunc("POST /oauth2/revoke", wrap(a.oauthRevoke))
	for _, p := range []string{"/oauth2/token", "/oauth2/userinfo", "/oauth2/revoke", "/oauth2/{slug}/jwks"} {
		mux.HandleFunc("OPTIONS "+p, oauthPreflight)
	}
}
func oauthPreflight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.WriteHeader(204)
}
func (a *App) oauthIssuer(c db.Client) string {
	return strings.TrimRight(a.Config.Domain, "/") + "/oauth2/" + url.PathEscape(c.Slug)
}
func (a *App) oauthClient(r *http.Request) (db.Client, error) {
	c, e := a.Q.ClientBySlug(r.Context(), r.PathValue("slug"))
	if e == nil && (c.Disabled || c.DeletedAt != nil || c.ClientType != "Oidc") {
		e = oauthInvalid
	}
	return c, e
}
func (a *App) oauthDiscovery(w http.ResponseWriter, r *http.Request) {
	c, e := a.oauthClient(r)
	if e == nil {
		oauthSubject(r, c, nil, nil)
	}
	if e != nil {
		if !notFound(e) && !errors.Is(e, oauthInvalid) {
			a.oauthServerError(w, r, e)
			return
		}
		oauthError(w, "invalid_client")
		return
	}
	b := strings.TrimRight(a.Config.Domain, "/") + "/oauth2"
	jsonResponse(w, 200, map[string]any{"issuer": a.oauthIssuer(c), "authorization_endpoint": b + "/authorize", "token_endpoint": b + "/token", "userinfo_endpoint": b + "/userinfo", "revocation_endpoint": b + "/revoke", "event_endpoint": b + "/event", "response_modes_supported": []string{"query"}, "revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}, "request_parameter_supported": false, "request_uri_parameter_supported": false, "introspection_endpoint": b + "/introspect", "introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}, "backchannel_logout_supported": true, "backchannel_logout_session_supported": true, "claims_supported": []string{"sid", "iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "name", "username", "preferred_username", "email", "groups"}, "jwks_uri": a.oauthIssuer(c) + "/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "subject_types_supported": []string{"pairwise"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}, "code_challenge_methods_supported": []string{"plain", "S256"}, "scopes_supported": []string{"openid", "profile", "email", "groups"}})
}
func (a *App) oauthKey(ctx context.Context, q *db.Queries, c db.Client) (db.SigningKey, *rsa.PrivateKey, error) {
	ks, e := q.SigningKeysByClientId(ctx, c.ID)
	if e != nil {
		return db.SigningKey{}, nil, e
	}
	for i := len(ks) - 1; i >= 0; i-- {
		if ks[i].ExpiresAt.After(time.Now().Add(15 * time.Minute)) {
			k, e := x509.ParsePKCS1PrivateKey(ks[i].Key)
			return ks[i], k, e
		}
	}
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return db.SigningKey{}, nil, e
	}
	s, e := q.CreateSigningKey(ctx, db.CreateSigningKeyParams{ClientID: c.ID, Key: x509.MarshalPKCS1PrivateKey(k), ExpiresAt: time.Now().Add(90 * 24 * time.Hour)})
	return s, k, e
}
func (a *App) oauthJWKS(w http.ResponseWriter, r *http.Request) {
	c, e := a.oauthClient(r)
	if e == nil {
		oauthSubject(r, c, nil, nil)
	}
	if e != nil {
		if !notFound(e) && !errors.Is(e, oauthInvalid) {
			a.oauthServerError(w, r, e)
			return
		}
		oauthError(w, "invalid_client")
		return
	}
	keys := []any{}
	e = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		c, e = q.LockClientByClientId(r.Context(), c.ClientID)
		if e != nil {
			return e
		}
		_, _, e = a.oauthKey(r.Context(), q, c)
		if e != nil {
			return e
		}
		ks, e := q.SigningKeysByClientId(r.Context(), c.ID)
		if e != nil {
			return e
		}
		for _, s := range ks {
			if !s.ExpiresAt.After(time.Now()) {
				continue
			}
			k, e := x509.ParsePKCS1PrivateKey(s.Key)
			if e != nil {
				return e
			}
			keys = append(keys, map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": fmt.Sprint(s.ID), "n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())})
		}
		return nil
	})
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	jsonResponse(w, 200, map[string]any{"keys": keys})
}
func oauthCallback(w http.ResponseWriter, r *http.Request, redirect string, v url.Values) {
	u, _ := url.Parse(redirect)
	q := u.Query()
	for k, x := range v {
		q[k] = x
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), 303)
}
func oauthScope(s string) bool {
	for _, v := range strings.Fields(s) {
		if v != "openid" && v != "email" && v != "profile" && v != "groups" {
			return false
		}
	}
	return true
}
func (a *App) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	f, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || !oauthUnique(f) {
		oauthError(w, "invalid_request")
		return
	}
	c, e := a.Q.ClientByClientId(r.Context(), f.Get("client_id"))
	if e != nil || c.Disabled || c.DeletedAt != nil {
		if e != nil && !notFound(e) {
			a.oauthServerError(w, r, e)
			return
		}
		oauthError(w, "invalid_client")
		return
	}
	oauthSubject(r, c, nil, nil)
	if who, ok := a.user(r); ok {
		oauthSubject(r, c, &who.User.ID, &who.Session.ID)
	}
	if c.ClientType == "ForwardAuth" {
		a.authorizeForward(w, r, c, f)
		return
	}
	redirect := f.Get("redirect_uri")
	if _, e = security.URL(redirect); e != nil || strings.Contains(redirect, "#") {
		oauthError(w, "invalid_request")
		return
	}
	rs, e := a.Q.ClientRedirectsByClientId(r.Context(), c.ID)
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	valid := false
	for _, x := range rs {
		valid = valid || x.RedirectUri == redirect
	}
	if !valid {
		oauthError(w, "invalid_request")
		return
	}
	failure := func(code string) {
		v := url.Values{"error": {code}}
		if _, ok := f["state"]; ok {
			v.Set("state", f.Get("state"))
		}
		oauthCallback(w, r, redirect, v)
	}
	if c.ClientType != "Oidc" || f.Get("client_type") != "" && f.Get("client_type") != "oidc" || f.Get("response_mode") != "" && f.Get("response_mode") != "query" || f.Has("request") || f.Has("request_uri") {
		failure("invalid_request")
		return
	}
	if f.Get("response_type") != "code" {
		failure("unsupported_response_type")
		return
	}
	if !oauthScope(f.Get("scope")) {
		failure("invalid_scope")
		return
	}
	challenge, method := f.Get("code_challenge"), f.Get("code_challenge_method")
	if !f.Has("code_challenge_method") {
		method = "plain"
	}
	if f.Has("code_challenge") {
		valid = false
		if method == "plain" {
			valid = oauthVerifier(challenge)
		}
		if method == "S256" {
			b, err := base64.RawURLEncoding.DecodeString(challenge)
			valid = err == nil && len(b) == 32 && len(challenge) == 43
		}
		if !valid {
			failure("invalid_request")
			return
		}
	} else if c.RequirePkce || f.Has("code_challenge_method") {
		failure("invalid_request")
		return
	}
	prompt := f.Get("prompt")
	if prompt != "" && prompt != "login" && prompt != "none" {
		failure("invalid_request")
		return
	}
	var age uint64
	if f.Has("max_age") {
		age, e = strconv.ParseUint(f.Get("max_age"), 10, 64)
		if e != nil {
			failure("invalid_request")
			return
		}
	}
	v, ok := a.user(r)
	reauth := prompt == "login" || ok && f.Has("max_age") && (age == 0 || v.Session.AuthTime <= 0 || uint64(max(0, time.Now().Unix()-v.Session.AuthTime)) > age)
	if !ok || reauth {
		if prompt == "none" {
			failure("login_required")
			return
		}
		http.Redirect(w, r, oauthLoginRedirect(f), 303)
		return
	}
	code := security.Token()
	e = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		locked, e := q.LockClientByClientId(r.Context(), c.ClientID)
		if e != nil {
			return e
		}
		if locked.Disabled || locked.DeletedAt != nil || locked.ClientType != "Oidc" {
			return oauthInvalid
		}
		c = locked
		fresh, e := a.sessionByID(r.Context(), q, v.Session.ID)
		if e != nil {
			return e
		}
		if fresh == nil || fresh.User.ID != v.User.ID {
			return oauthInvalid
		}
		allowed, e := a.permitted(r.Context(), q, c.ID, v.User.ID)
		if e != nil {
			return e
		}
		if !allowed {
			return oauthInvalid
		}
		_, e = q.CreateAuthorizationCode(r.Context(), db.CreateAuthorizationCodeParams{ClientID: c.ID, UserID: v.User.ID, SessionID: v.Session.ID, TokenHash: security.Hash(code), RedirectUri: redirect, PkceChallenge: challenge, PkceMethod: method, Scope: strings.Join(strings.Fields(f.Get("scope")), " "), Nonce: f.Get("nonce"), ExpiresAt: time.Now().Add(5 * time.Minute)})
		if e != nil {
			return e
		}
		return a.audit(r.Context(), q, v.User.ID, "OAuthAuthorization", map[string]any{"client_id": c.ID})
	})
	if errors.Is(e, oauthInvalid) {
		failure("access_denied")
		return
	}
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	out := url.Values{"code": {code}}
	if f.Has("state") {
		out.Set("state", f.Get("state"))
	}
	oauthCallback(w, r, redirect, out)
}
func oauthForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if r.URL.RawQuery != "" || r.ParseForm() != nil || !oauthUnique(r.PostForm) {
		oauthError(w, "invalid_request")
		return nil, false
	}
	return r.PostForm, true
}
func (a *App) oauthAuthenticate(ctx context.Context, q *db.Queries, r *http.Request, f url.Values) (db.Client, error) {
	id, secret := f.Get("client_id"), f.Get("client_secret")
	if len(r.Header.Values("Authorization")) > 1 {
		return db.Client{}, oauthInvalid
	}
	if r.Header.Get("Authorization") != "" {
		if f.Has("client_id") || f.Has("client_secret") {
			return db.Client{}, oauthInvalid
		}
		x, y, ok := r.BasicAuth()
		if !ok {
			return db.Client{}, oauthInvalid
		}
		var e error
		id, e = url.QueryUnescape(x)
		if e != nil {
			return db.Client{}, oauthInvalid
		}
		secret, e = url.QueryUnescape(y)
		if e != nil {
			return db.Client{}, oauthInvalid
		}
	}
	c, e := q.LockClientByClientId(ctx, id)
	if e != nil {
		return c, e
	}
	if c.Disabled || c.DeletedAt != nil || c.ClientType != "Oidc" || secret == "" || !security.Equal(secret, c.ClientSecret) {
		return c, oauthInvalid
	}
	return c, nil
}

// oidcSubject derives a stable per-client subject without additional stored state.
func (a *App) oidcSubject(c db.Client, userID ids.UserID) string {
	mac := hmac.New(sha256.New, []byte(fmt.Sprint(userID)))
	mac.Write([]byte(c.ClientID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) oauthIdentity(c db.Client, u db.User, scope string) map[string]any {
	v := map[string]any{"sub": a.oidcSubject(c, u.ID)}
	for _, s := range strings.Fields(scope) {
		if s == "profile" {
			v["username"] = u.Username
			v["preferred_username"] = u.Username
			v["name"] = u.Username
		}
		if s == "email" && u.Email != "" {
			v["email"] = u.Email
		}
	}
	return v
}

// Resolve scope-gated group memberships at issuance and on every UserInfo request.
func (a *App) oauthIdentityClaims(ctx context.Context, q *db.Queries, c db.Client, u db.User, scope string) (map[string]any, error) {
	claims := a.oauthIdentity(c, u, scope)
	for _, s := range strings.Fields(scope) {
		if s == "groups" {
			names, err := q.ActiveGroupNamesForUser(ctx, u.ID)
			if err != nil {
				return nil, err
			}
			claims["groups"] = names
			break
		}
	}
	return claims, nil
}

func (a *App) oauthMint(ctx context.Context, q *db.Queries, c db.Client, v *identity, t db.CreateOAuthTokenParams) (map[string]any, error) {
	now := time.Now()
	if !t.ExpiresAt.After(now) {
		return nil, oauthInvalid
	}
	access, refresh := security.Token(), security.Token()
	t.AccessTokenHash = security.Hash(access)
	t.RefreshTokenHash = security.Hash(refresh)
	t.AccessExpiresAt = now.Add(15 * time.Minute)
	if t.ExpiresAt.Before(t.AccessExpiresAt) {
		t.AccessExpiresAt = t.ExpiresAt
	}
	out := map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": max(0, t.AccessExpiresAt.Unix()-now.Unix()), "scope": t.Scope}
	if strings.Contains(" "+t.Scope+" ", " openid ") {
		s, k, e := a.oauthKey(ctx, q, c)
		if e != nil {
			return nil, e
		}
		sid, e := a.oauthSID(ctx, q, c, v)
		if e != nil {
			return nil, e
		}
		claims, e := a.oauthIdentityClaims(ctx, q, c, v.User, t.Scope)
		if e != nil {
			return nil, e
		}
		claims["sid"] = sid
		claims["iss"] = a.oauthIssuer(c)
		claims["aud"] = c.ClientID
		claims["iat"] = now.Unix()
		claims["exp"] = t.AccessExpiresAt.Unix()
		if t.AuthTime > 0 {
			claims["auth_time"] = t.AuthTime
		}
		if t.Nonce != "" {
			claims["nonce"] = t.Nonce
		}
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": fmt.Sprint(s.ID)})
		b, e := json.Marshal(claims)
		if e != nil {
			return nil, e
		}
		payload := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
		hash := sha256.Sum256([]byte(payload))
		sig, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hash[:])
		if e != nil {
			return nil, e
		}
		out["id_token"] = payload + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	_, e := q.CreateOAuthToken(ctx, t)
	if e == nil {
		e = a.audit(ctx, q, v.User.ID, "OAuthTokenIssued", map[string]any{"client_id": c.ID, "session_id": v.Session.ID})
	}
	return out, e
}
func (a *App) oauthGrantIdentity(ctx context.Context, q *db.Queries, c db.Client, user ids.UserID, session ids.SessionID) (*identity, error) {
	v, e := a.sessionByID(ctx, q, session)
	if e != nil {
		return nil, e
	}
	if v == nil || v.User.ID != user {
		return nil, oauthInvalid
	}
	ok, e := a.permitted(ctx, q, c.ID, user)
	if e != nil {
		return nil, e
	}
	if !ok {
		return nil, oauthInvalid
	}
	return v, nil
}
func (a *App) oauthToken(w http.ResponseWriter, r *http.Request) {
	f, ok := oauthForm(w, r)
	if !ok {
		return
	}
	var out map[string]any
	protocol := ""
	ctx := r.Context()
	e := transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, e := a.oauthAuthenticate(ctx, q, r, f)
		oauthSubject(r, c, nil, nil)
		if e != nil {
			protocol = "invalid_client"
			if notFound(e) || errors.Is(e, oauthInvalid) {
				return nil
			}
			return e
		}
		now := time.Now()
		var t db.CreateOAuthTokenParams
		switch f.Get("grant_type") {
		case "authorization_code":
			code, e := q.LockAuthorizationCodeByTokenHash(ctx, security.Hash(f.Get("code")))
			if notFound(e) {
				protocol = "invalid_grant"
				return nil
			}
			if e != nil {
				return e
			}
			if code.ClientID == c.ID {
				oauthSubject(r, c, &code.UserID, &code.SessionID)
			}
			if f.Get("code") == "" || code.ClientID != c.ID || code.RedirectUri != f.Get("redirect_uri") || code.PkceChallenge != "" && !oauthPKCE(f.Get("code_verifier"), code.PkceChallenge, code.PkceMethod) {
				protocol = "invalid_grant"
				return nil
			}
			if code.ConsumedAt != nil {
				protocol = "invalid_grant"
				if e := q.OAuthRevokeCode(ctx, code.ID); e != nil {
					return e
				}
				return a.audit(ctx, q, code.UserID, "OAuthReplayDetected", map[string]any{"client_id": c.ID, "grant": "authorization_code"})
			}
			if !code.ExpiresAt.After(now) {
				protocol = "invalid_grant"
				return nil
			}
			v, e := a.oauthGrantIdentity(ctx, q, c, code.UserID, code.SessionID)
			if errors.Is(e, oauthInvalid) {
				protocol = "invalid_grant"
				return nil
			}
			if e != nil {
				return e
			}
			if e = q.OAuthConsumeCode(ctx, code.ID); e != nil {
				return e
			}
			expiry := now.Add(time.Duration(c.SessionLifetimeS) * time.Second)
			if v.Session.ExpiresAt.Before(expiry) {
				expiry = v.Session.ExpiresAt
			}
			t = db.CreateOAuthTokenParams{ClientID: c.ID, UserID: code.UserID, SessionID: code.SessionID, CodeID: code.ID, Family: security.Token(), Scope: code.Scope, Nonce: code.Nonce, AuthTime: v.Session.AuthTime, ExpiresAt: expiry}
			out, e = a.oauthMint(ctx, q, c, v, t)
			return e
		case "refresh_token":
			old, e := q.LockOAuthTokenByRefreshTokenHash(ctx, security.Hash(f.Get("refresh_token")))
			if notFound(e) {
				protocol = "invalid_grant"
				return nil
			}
			if e != nil {
				return e
			}
			if old.ClientID == c.ID {
				oauthSubject(r, c, &old.UserID, &old.SessionID)
			}
			if f.Get("refresh_token") == "" || old.ClientID != c.ID {
				protocol = "invalid_grant"
				return nil
			}
			if old.RevokedAt != nil {
				protocol = "invalid_grant"
				if e := q.OAuthRevokeFamily(ctx, old.Family); e != nil {
					return e
				}
				return a.audit(ctx, q, old.UserID, "OAuthReplayDetected", map[string]any{"client_id": c.ID, "grant": "refresh_token"})
			}
			if !old.ExpiresAt.After(now) {
				protocol = "invalid_grant"
				return nil
			}
			scope := old.Scope
			if f.Has("scope") {
				scope = strings.Join(strings.Fields(f.Get("scope")), " ")
				for _, s := range strings.Fields(scope) {
					if !strings.Contains(" "+old.Scope+" ", " "+s+" ") {
						protocol = "invalid_scope"
						return nil
					}
				}
			}
			v, e := a.oauthGrantIdentity(ctx, q, c, old.UserID, old.SessionID)
			if errors.Is(e, oauthInvalid) {
				protocol = "invalid_grant"
				return nil
			}
			if e != nil {
				return e
			}
			if e = q.OAuthRevokeToken(ctx, old.ID); e != nil {
				return e
			}
			t = db.CreateOAuthTokenParams{ClientID: c.ID, UserID: old.UserID, SessionID: old.SessionID, CodeID: old.CodeID, Family: old.Family, Scope: scope, Nonce: old.Nonce, AuthTime: v.Session.AuthTime, ExpiresAt: old.ExpiresAt}
			out, e = a.oauthMint(ctx, q, c, v, t)
			return e
		default:
			protocol = "unsupported_grant_type"
			return nil
		}
	})
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	if protocol != "" {
		oauthError(w, protocol)
		return
	}
	jsonResponse(w, 200, out)
}
func (a *App) oauthUserinfo(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 || !strings.HasPrefix(h[0], "Bearer ") || strings.ContainsAny(strings.TrimPrefix(h[0], "Bearer "), " \t\r\n") {
		oauthError(w, "invalid_token")
		return
	}
	t, e := a.Q.OAuthTokenByAccessTokenHash(r.Context(), security.Hash(strings.TrimPrefix(h[0], "Bearer ")))
	if notFound(e) {
		oauthError(w, "invalid_token")
		return
	}
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	if t.RevokedAt != nil || !t.ExpiresAt.After(time.Now()) || !t.AccessExpiresAt.After(time.Now()) {
		oauthError(w, "invalid_token")
		return
	}
	c, e := a.Q.GetClient(r.Context(), t.ClientID)
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	oauthSubject(r, c, &t.UserID, &t.SessionID)
	if c.Disabled || c.DeletedAt != nil || c.ClientType != "Oidc" {
		oauthError(w, "invalid_token")
		return
	}
	v, e := a.oauthGrantIdentity(r.Context(), a.Q, c, t.UserID, t.SessionID)
	if errors.Is(e, oauthInvalid) {
		oauthError(w, "invalid_token")
		return
	}
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	if !strings.Contains(" "+t.Scope+" ", " openid ") {
		jsonResponse(w, 403, map[string]string{"error": "insufficient_scope"})
		return
	}
	claims, e := a.oauthIdentityClaims(r.Context(), a.Q, c, v.User, t.Scope)
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	jsonResponse(w, 200, claims)
}
func (a *App) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	f, ok := oauthForm(w, r)
	if !ok {
		return
	}
	protocol := ""
	e := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		c, e := a.oauthAuthenticate(r.Context(), q, r, f)
		oauthSubject(r, c, nil, nil)
		if notFound(e) || errors.Is(e, oauthInvalid) {
			protocol = "invalid_client"
			return nil
		}
		if e != nil {
			return e
		}
		if f.Get("token") == "" {
			protocol = "invalid_request"
			return nil
		}
		hash := security.Hash(f.Get("token"))
		t, e := q.OAuthTokenByRefreshTokenHash(r.Context(), hash)
		if notFound(e) {
			t, e = q.OAuthTokenByAccessTokenHash(r.Context(), hash)
		}
		if notFound(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if t.ClientID != c.ID {
			return nil
		}
		oauthSubject(r, c, &t.UserID, &t.SessionID)
		if e = q.OAuthRevokeFamily(r.Context(), t.Family); e != nil {
			return e
		}
		return a.audit(r.Context(), q, t.UserID, "OAuthTokenRevoked", map[string]any{"client_id": c.ID})
	})
	if e != nil {
		a.oauthServerError(w, r, e)
		return
	}
	if protocol != "" {
		oauthError(w, protocol)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
}
