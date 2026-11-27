package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *App) initialize() error {
	a.secret = security.Token()
	var err error
	a.dummyPassword, err = security.HashPassword(security.Token())
	return err
}
func (a *App) Bootstrap(ctx context.Context) error {
	_, err := a.Q.GetUser(ctx, 0)
	if err == nil {
		return nil
	}
	if !notFound(err) {
		return err
	}
	password := security.Token()
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = a.Q.BootstrapUser(ctx, db.BootstrapUserParams{Password: hash, WebauthnUserID: []byte(security.Token())})
	if notFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	slog.Warn("Created initial administrator; save this password and protect startup logs", "username", "system", "password", password)
	return nil
}

// Keep the PKCE verifier private while binding the public state to its provider.
func upstreamState(internalToken, providerID string) string {
	mac := hmac.New(sha256.New, []byte(internalToken))
	mac.Write([]byte("guard-upstream-oidc-state\x00"))
	mac.Write([]byte(providerID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	providers, err := a.Q.EnabledUpstreamProviders(r.Context())
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	method := r.PathValue("method")
	if method == "" && len(providers) == 0 && !a.Config.PasswordDisabled {
		method = "password"
	}
	var selected *db.UpstreamProvider
	for _, p := range providers {
		if p.Slug == method {
			copy := p
			selected = &copy
			break
		}
	}
	if method != "" && method != "password" && selected == nil {
		http.NotFound(w, r)
		return
	}
	if method == "password" && a.Config.PasswordDisabled {
		a.fail(w, r, 404, "Password login is disabled.")
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !oauthUnique(params) || params.Get("prompt") != "" && params.Get("prompt") != "login" {
		a.fail(w, r, 400, "Invalid login parameters.")
		return
	}
	state := upstreamLoginState{ForceLogin: params.Get("prompt") == "login"}
	if params.Has("max_age") {
		age, err := strconv.ParseUint(params.Get("max_age"), 10, 64)
		if err != nil {
			a.fail(w, r, 400, "Invalid max_age.")
			return
		}
		state.MaxAge = &age
	}
	if selected != nil && selected.ConfigurationMode == "oauth2" && (state.ForceLogin || state.MaxAge != nil) {
		a.fail(w, r, 400, "This provider cannot verify authentication freshness. Choose password login or an OpenID Connect provider.")
		return
	}
	if selected != nil {
		state.Nonce = security.Token()
		state.ProviderID = selected.ID
		state.Revision = selected.Revision
	}
	if state.ForceLogin {
		hash, e := a.samlLoginBinding(r)
		if e != nil {
			a.adminResult(w, r, e)
			return
		}
		state.SAMLRequestHash = hash
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	token := security.Token()
	login, err := a.Q.CreateLoginSession(r.Context(), db.CreateLoginSessionParams{TokenHash: security.Hash(token), InternalToken: security.Token(), RedirectUri: security.SafeRedirect(r.URL.Query().Get("r")), Provider: method, State: encoded, ExpiresAt: time.Now().Add(10 * time.Minute)})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.setCookie(w, "login_session", token, 600)
	if p := selected; p != nil {
		u, err := url.Parse(p.AuthorizeUrl)
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		q := u.Query()
		q.Set("client_id", p.ClientID)
		q.Set("redirect_uri", a.Config.Domain+"/login/"+p.Slug+"/callback")
		q.Set("response_type", "code")
		q.Set("scope", p.Scopes)
		q.Set("state", upstreamState(login.InternalToken, p.Slug))
		if p.ConfigurationMode != "oauth2" {
			q.Set("nonce", state.Nonce)
			if state.MaxAge != nil {
				q.Set("max_age", strconv.FormatUint(*state.MaxAge, 10))
			}
			if state.ForceLogin {
				q.Set("prompt", "login")
				q.Set("max_age", "0")
			}
		}
		if p.Pkce {
			q.Set("code_challenge", security.Hash(login.InternalToken))
			q.Set("code_challenge_method", "S256")
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), 303)
		return
	}
	if method == "password" {
		a.passwordPage(w, r, login, "")
		return
	}
	type choice struct{ ID, Name string }
	choices := []choice{}
	for _, p := range providers {
		choices = append(choices, choice{p.Slug, p.Name})
	}
	if !a.Config.PasswordDisabled {
		choices = append(choices, choice{"password", "Password"})
	}
	a.page(w, r, "Sign in", loginChoicesTemplate, map[string]any{"Choices": choices, "Redirect": login.RedirectUri, "Prompt": params.Get("prompt"), "MaxAge": params.Get("max_age")})
}
func (a *App) passwordPage(w http.ResponseWriter, r *http.Request, login db.LoginSession, message string) {
	a.page(w, r, "Sign in", passwordTemplate, map[string]any{"Login": login, "Error": message})
}
func (a *App) loginSession(r *http.Request) (db.LoginSession, error) {
	token := cookieValue(r, "login_session")
	if token == "" {
		return db.LoginSession{}, errors.New("missing login session")
	}
	s, err := a.Q.LoginSessionByTokenHash(r.Context(), security.Hash(token))
	if err != nil {
		return s, err
	}
	if !s.ExpiresAt.After(time.Now()) {
		return s, errors.New("expired login session")
	}
	return s, nil
}
func (a *App) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if a.Config.PasswordDisabled || r.PathValue("method") != "password" && r.PathValue("method") != "" {
		a.fail(w, r, 404, "Unknown login method.")
		return
	}
	if retry := a.allowLogin(a.requestIP(r)); retry > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(retry))
		a.fail(w, r, 429, "Too many login attempts. Try again later.")
		return
	}
	login, err := a.loginSession(r)
	if err != nil || login.Provider != "password" || !security.Equal(r.PostForm.Get("login_token"), login.InternalToken) {
		a.fail(w, r, 400, "This login has expired. Start again.")
		return
	}
	if len(r.PostForm["email"]) != 1 || len(r.PostForm["password"]) != 1 {
		a.fail(w, r, 400, "Invalid login fields.")
		return
	}
	user, err := a.Q.UserByUsername(r.Context(), r.PostForm.Get("email"))
	if err != nil && !notFound(err) {
		a.serverError(w, r, err)
		return
	}
	hash := a.dummyPassword
	if err == nil && !user.Disabled && user.DeletedAt == nil && user.Password != "" {
		hash = user.Password
	}
	select {
	case a.workers <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	accepted := security.VerifyPassword(r.PostForm.Get("password"), hash)
	<-a.workers
	if !accepted || err != nil || user.Disabled || user.DeletedAt != nil || user.Password == "" {
		if err == nil {
			if err = a.audit(r.Context(), a.Q, user.ID, "LoginFailed", map[string]string{"ip": a.requestIP(r)}); err != nil {
				slog.Error("login failure audit", "error", err)
			}
		}
		w.WriteHeader(401)
		a.passwordPage(w, r, login, "Invalid username or password.")
		return
	}
	if err = a.afterPrimary(w, r, user, login); err != nil {
		a.serverError(w, r, err)
	}
}
func (a *App) afterPrimary(w http.ResponseWriter, r *http.Request, user db.User, login db.LoginSession) error {
	totp, err := a.Q.TotpAuthenticatorsByUserId(r.Context(), user.ID)
	if err != nil {
		return err
	}
	keys, err := a.Q.WebauthnCredentialsByUserId(r.Context(), user.ID)
	if err != nil {
		return err
	}
	if len(totp)+len(keys) > 0 {
		return a.startMFA(w, r, user, login)
	}
	return a.finishLogin(w, r, user, login)
}
func (a *App) finishLogin(w http.ResponseWriter, r *http.Request, user db.User, login db.LoginSession) error {
	raw := security.Token()
	err := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		binding, err := lockUpstreamPending(r.Context(), q, login)
		if err != nil {
			return err
		}
		current, err := q.LockUser(r.Context(), user.ID)
		if err != nil {
			return err
		}
		if current.Disabled || current.DeletedAt != nil || current.MfaRevision != user.MfaRevision {
			return errors.New("account changed during sign-in")
		}
		if binding != nil {
			if binding.UserID != current.ID || !strings.EqualFold(binding.MatchedEmail, current.Email) {
				return errUpstreamSessionChanged
			}
			matches, err := q.UsersByEmail(r.Context(), binding.MatchedEmail)
			if err != nil {
				return err
			}
			if len(matches) != 1 || matches[0].ID != current.ID {
				return errUpstreamSessionChanged
			}
		}
		locked, err := q.LockLoginSession(r.Context(), login.ID)
		if err != nil {
			return err
		}
		if !locked.ExpiresAt.After(time.Now()) || !security.Equal(locked.TokenHash, security.Hash(cookieValue(r, "login_session"))) {
			return errors.New("expired login")
		}
		issued, err := q.CreateSession(r.Context(), db.CreateSessionParams{UserID: user.ID, TokenHash: security.Hash(raw), ExpiresAt: time.Now().Add(SessionLifetime)})
		if err != nil {
			return err
		}
		var loginState upstreamLoginState
		if err = json.Unmarshal(locked.State, &loginState); err != nil {
			return err
		}
		if loginState.SAMLRequestHash != "" {
			if err = q.RecordSAMLAuthentication(r.Context(), db.RecordSAMLAuthenticationParams{SessionID: issued.ID, RequestHash: loginState.SAMLRequestHash}); err != nil {
				return err
			}
		}
		if binding != nil {
			var state upstreamLoginState
			if err = json.Unmarshal(locked.State, &state); err != nil {
				return err
			}
			if err = q.SetSessionAuthTime(r.Context(), db.SetSessionAuthTimeParams{ID: issued.ID, AuthTime: state.AuthTime}); err != nil {
				return err
			}
			if err = q.BindUpstreamSession(r.Context(), db.BindUpstreamSessionParams{SessionID: issued.ID, ProviderID: binding.ProviderID, Subject: binding.Subject, Sid: binding.Sid, ProviderRevision: binding.ProviderRevision, TokenIssuedAt: binding.TokenIssuedAt}); err != nil {
				return err
			}
		}
		if err = q.DeleteLoginSession(r.Context(), login.ID); err != nil {
			return err
		}
		return a.audit(r.Context(), q, user.ID, "UserLoggedIn", map[string]string{"ip": a.requestIP(r)})
	})
	if err != nil {
		return err
	}
	a.setCookie(w, "session", raw, int(SessionLifetime.Seconds()))
	a.setCookie(w, "login_session", "", -1)
	a.setCookie(w, "mfa_pending", "", -1)
	http.Redirect(w, r, security.SafeRedirect(login.RedirectUri), 303)
	return nil
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	v, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	err := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		if err := q.DeleteSession(r.Context(), v.Session.ID); err != nil {
			return err
		}
		return a.audit(r.Context(), q, v.User.ID, "UserLoggedOut", map[string]any{"session_id": v.Session.ID})
	})
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	a.setCookie(w, "session", "", -1)
	http.Redirect(w, r, "/login", 303)
}
func (a *App) upstreamCallback(w http.ResponseWriter, r *http.Request) {
	p, err := a.provider(r.Context(), r.PathValue("method"))
	if err != nil {
		if notFound(err) {
			a.fail(w, r, 405, "This login method does not accept callbacks.")
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	login, err := a.loginSession(r)
	if err != nil || login.Provider != p.Slug {
		a.fail(w, r, 400, "This login has expired. Start again.")
		return
	}
	var state upstreamLoginState
	if json.Unmarshal(login.State, &state) != nil || state.ProviderID != p.ID || state.Revision != p.Revision || state.Nonce == "" {
		a.fail(w, r, 400, "Provider settings changed. Start again.")
		return
	}
	fields, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !oauthUnique(fields) {
		a.fail(w, r, 400, "Invalid callback parameters.")
		return
	}
	if !security.Equal(fields.Get("state"), upstreamState(login.InternalToken, p.Slug)) || fields.Get("code") == "" {
		a.fail(w, r, 400, "Invalid upstream state or code.")
		return
	}
	err = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		current, err := q.LockUpstreamProvider(r.Context(), p.ID)
		if err != nil {
			return err
		}
		if !current.Enabled || current.DeletedAt != nil || current.Revision != p.Revision {
			return errUpstreamSessionChanged
		}
		s, err := q.LockLoginSession(r.Context(), login.ID)
		if err != nil {
			return err
		}
		var st upstreamLoginState
		if json.Unmarshal(s.State, &st) != nil || st.Exchanged || !s.ExpiresAt.After(time.Now()) {
			return errUpstreamSessionChanged
		}
		st.Exchanged = true
		encoded, err := json.Marshal(st)
		if err != nil {
			return err
		}
		_, err = q.UpdateLoginSession(r.Context(), db.UpdateLoginSessionParams{ID: s.ID, TokenHash: s.TokenHash, InternalToken: s.InternalToken, RedirectUri: s.RedirectUri, Provider: s.Provider, State: encoded, ExpiresAt: s.ExpiresAt})
		return err
	})
	if err != nil {
		if errors.Is(err, errUpstreamSessionChanged) || notFound(err) {
			a.fail(w, r, 400, "This callback has expired or already been used.")
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {fields.Get("code")}, "redirect_uri": {a.Config.Domain + "/login/" + p.Slug + "/callback"}}
	if p.Pkce {
		form.Set("code_verifier", login.InternalToken)
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", p.TokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *a.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		a.fail(w, r, 502, "Upstream token exchange failed.")
		return
	}
	defer resp.Body.Close()
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.fail(w, r, 502, "Upstream token exchange failed. Check the provider configuration.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(body) > 65536 || strictJSON(body, &tokens) != nil || tokens.AccessToken == "" || tokens.TokenType != "" && !strings.EqualFold(tokens.TokenType, "Bearer") || p.ConfigurationMode != "oauth2" && tokens.IDToken == "" {
		a.fail(w, r, 502, "Invalid upstream token response.")
		return
	}
	identityClaims := upstreamClaims{IssuedAt: time.Now().Unix()}
	if p.ConfigurationMode != "oauth2" {
		identityClaims, err = a.verifyUpstreamJWT(r.Context(), p, tokens.IDToken, upstreamIDToken, state.Nonce)
		if err != nil {
			if errors.Is(err, errUpstreamJWKSUnavailable) {
				a.fail(w, r, 503, "Upstream signing keys are unavailable.")
			} else {
				a.fail(w, r, 403, "Invalid upstream ID token.")
			}
			return
		}
	}
	if !upstreamAuthenticationFresh(identityClaims, state, login.CreatedAt) {
		a.fail(w, r, 403, "The upstream provider did not confirm a sufficiently recent authentication.")
		return
	}
	req, err = http.NewRequestWithContext(r.Context(), "GET", p.UserinfoUrl, nil)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	info, err := client.Do(req)
	if err != nil {
		a.fail(w, r, 502, "Upstream user information failed.")
		return
	}
	defer info.Body.Close()
	var claims upstreamProfile
	body, err = io.ReadAll(io.LimitReader(info.Body, 65537))
	valid := err == nil && len(body) <= 65536 && info.StatusCode == 200
	if valid && p.ConfigurationMode == "oauth2" {
		claims, err = parseOAuth2Profile(body, p)
		valid = err == nil
		identityClaims.Subject = claims.Subject
	} else if valid {
		var oidc struct {
			Subject  string `json:"sub"`
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		valid = strictJSON(body, &oidc) == nil && oidc.Subject == identityClaims.Subject && oidc.Verified && validEmail(oidc.Email)
		claims = upstreamProfile{Subject: oidc.Subject, Email: oidc.Email, Verified: oidc.Verified}
	}
	if !valid {
		a.fail(w, r, 403, "The upstream provider must return matching identity and verified email.")
		return
	}

	users, err := a.Q.UsersByEmail(r.Context(), claims.Email)
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	if len(users) != 1 || !strings.EqualFold(users[0].Email, claims.Email) {
		a.fail(w, r, 403, "No unique active account matches the upstream email address.")
		return
	}
	if err = a.saveUpstreamBinding(r.Context(), p, users[0], login, identityClaims); err != nil {
		if errors.Is(err, errUpstreamSessionChanged) || notFound(err) {
			a.fail(w, r, 403, "Upstream session ended or provider settings changed. Start again.")
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	if err = a.afterPrimary(w, r, users[0], login); err != nil {
		if errors.Is(err, errUpstreamSessionChanged) || notFound(err) {
			a.fail(w, r, 403, "Upstream session ended. Start again.")
		} else {
			a.serverError(w, r, err)
		}
	}
}
func validEmail(s string) bool {
	parts := strings.Split(s, "@")
	return len(s) <= 254 && len(parts) == 2 && parts[0] != "" && parts[1] != "" && !strings.ContainsAny(s, " \t\r\n")
}
