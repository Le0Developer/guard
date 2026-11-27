package app

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/crewjam/saml"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/samlidp"
	"github.com/le0developer/guard/internal/security"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func (a *App) samlBase(c db.Client) string { return a.Config.Domain + "/saml/" + c.Slug }
func (a *App) samlConfig(ctx context.Context, q *db.Queries, c db.Client) (db.SamlClientConfig, samlidp.Config, error) {
	cfg, e := q.GetSAMLConfig(ctx, c.ID)
	out := samlidp.Config{Issuer: cfg.EntityID, SSO: a.samlBase(c) + "/sso", NameID: cfg.NameIDFormat, RequireSignature: cfg.RequireSignature}
	if e != nil {
		return cfg, out, e
	}
	eps, e := q.SAMLACS(ctx, c.ID)
	if e != nil {
		return cfg, out, e
	}
	for _, ep := range eps {
		out.ACS = append(out.ACS, samlidp.ACS{URL: ep.Url, Index: int(ep.EndpointIndex), Default: ep.IsDefault})
	}
	certs, e := q.SAMLSPCertificates(ctx, c.ID)
	if e != nil {
		return cfg, out, e
	}
	for _, c := range certs {
		cert, e := x509.ParseCertificate(c.Certificate)
		if e != nil {
			return cfg, out, e
		}
		out.Certificates = append(out.Certificates, cert)
	}
	return cfg, out, nil
}
func (a *App) samlClient(w http.ResponseWriter, r *http.Request, disabledOK bool) (db.Client, bool) {
	c, e := a.Q.ClientBySlug(r.Context(), r.PathValue("slug"))
	if notFound(e) || e == nil && (c.DeletedAt != nil || c.ClientType != "Saml") {
		http.NotFound(w, r)
		return c, false
	}
	if e != nil {
		a.serverError(w, r, e)
		return c, false
	}
	if c.Disabled && !disabledOK {
		a.fail(w, r, 403, "This application is disabled.")
		return c, false
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	return c, true
}
func (a *App) samlMetadata(w http.ResponseWriter, r *http.Request) {
	c, ok := a.samlClient(w, r, true)
	if !ok {
		return
	}
	cfg, e := a.Q.GetSAMLConfig(r.Context(), c.ID)
	if e != nil {
		a.serverError(w, r, e)
		return
	}
	keys, e := a.Q.SAMLKeys(r.Context(), c.ID)
	if e != nil {
		a.serverError(w, r, e)
		return
	}
	metadataURL, _ := url.Parse(a.samlBase(c) + "/metadata")
	ssoURL, _ := url.Parse(a.samlBase(c) + "/sso")
	idp := saml.IdentityProvider{MetadataURL: *metadataURL, SSOURL: *ssoURL}
	for _, k := range keys {
		cert, e := x509.ParseCertificate(k.Certificate)
		if e != nil {
			a.serverError(w, r, e)
			return
		}
		if idp.Certificate == nil {
			idp.Certificate = cert
		} else {
			idp.ExtraCertificates = append(idp.ExtraCertificates, cert)
		}
	}
	if idp.Certificate == nil {
		a.fail(w, r, 503, "SAML signing certificate unavailable.")
		return
	}
	m := idp.Metadata()
	d := &m.IDPSSODescriptors[0]
	d.SingleSignOnServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: ssoURL.String()}}
	d.KeyDescriptors = nil
	for _, k := range keys {
		d.KeyDescriptors = append(d.KeyDescriptors, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(k.Certificate)}}}}})
	}
	d.NameIDFormats = []saml.NameIDFormat{saml.NameIDFormat(cfg.NameIDFormat)}
	d.WantAuthnRequestsSigned = &cfg.RequireSignature
	b, e := xml.Marshal(m)
	if e != nil {
		a.serverError(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}
func (a *App) samlSSO(w http.ResponseWriter, r *http.Request) {
	c, ok := a.samlClient(w, r, false)
	if !ok {
		return
	}
	if wait := a.allowLogin("saml:" + a.requestIP(r)); wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(wait))
		a.samlFailure(r, c, "rate_limited")
		a.fail(w, r, 429, "Too many SAML requests.")
		return
	}
	cfg, policy, e := a.samlConfig(r.Context(), a.Q, c)
	if e != nil {
		a.serverError(w, r, e)
		return
	}
	now := time.Now().UTC()
	req, e := samlidp.ParseRedirect(r.URL.RawQuery, policy, now)
	if e != nil {
		a.samlFailure(r, c, "invalid_request")
		a.fail(w, r, 400, "Invalid or unsupported SAML request.")
		return
	}
	browser := cookieValue(r, "saml_browser")
	if len(browser) != 43 {
		browser = security.Token()
	}
	a.setCookie(w, "saml_browser", browser, 600)
	token := security.Token()
	data, _ := json.Marshal(req)
	// Client locking serializes settings changes with admission and bounds per-client
	// outstanding state across processes. Issuance takes this same lock first.
	e = transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		if e := q.LockSAMLAdmission(r.Context()); e != nil {
			return e
		}
		locked, e := q.LockClient(r.Context(), c.ID)
		if e != nil {
			return e
		}
		if locked.Disabled || locked.DeletedAt != nil {
			return adminError{403, "Application unavailable."}
		}
		current, e := q.GetSAMLConfig(r.Context(), c.ID)
		if e != nil {
			return e
		}
		if current.Revision != cfg.Revision {
			return adminError{409, "Application settings changed. Start again."}
		}
		_, e = q.CreateSAMLRequest(r.Context(), db.CreateSAMLRequestParams{ClientID: c.ID, RequestID: req.ID, TokenHash: security.Hash(token), BrowserHash: security.Hash(browser), Revision: cfg.Revision, Request: data, ExpiresAt: now.Add(10 * time.Minute)})
		return e
	})
	if e != nil {
		a.samlFailure(r, c, "admission_failed")
		var ae adminError
		if errors.As(e, &ae) {
			a.fail(w, r, ae.status, ae.message)
		} else if notFound(e) {
			a.fail(w, r, 429, "Too many pending SAML requests.")
		} else {
			var pe interface{ SQLState() string }
			if errors.As(e, &pe) && pe.SQLState() == "23505" {
				a.fail(w, r, 409, "SAML request already used.")
			} else {
				a.serverError(w, r, e)
			}
		}
		return
	}
	http.Redirect(w, r, "/saml/"+c.Slug+"/continue?t="+url.QueryEscape(token), 303)
}
func (a *App) samlPending(r *http.Request, c db.Client, q *db.Queries, lock bool) (db.SamlRequest, samlidp.Request, error) {
	var row db.SamlRequest
	var req samlidp.Request
	token := r.URL.Query().Get("t")
	if r.Method == "POST" {
		token = r.PostForm.Get("t")
	}
	var e error
	if lock {
		row, e = q.LockSAMLRequest(r.Context(), security.Hash(token))
	} else {
		row, e = q.GetSAMLRequest(r.Context(), security.Hash(token))
	}
	if e != nil {
		return row, req, e
	}
	if row.ClientID != c.ID || !security.Equal(row.BrowserHash, security.Hash(cookieValue(r, "saml_browser"))) {
		return row, req, adminError{403, "SAML request belongs to another browser."}
	}
	if row.ConsumedAt != nil {
		return row, req, adminError{409, "SAML request already used."}
	}
	if !row.ExpiresAt.After(time.Now()) {
		return row, req, adminError{410, "SAML request expired. Start again."}
	}
	e = json.Unmarshal(row.Request, &req)
	return row, req, e
}
func (a *App) samlContinue(w http.ResponseWriter, r *http.Request) {
	c, ok := a.samlClient(w, r, false)
	if !ok {
		return
	}
	row, req, e := a.samlPending(r, c, a.Q, false)
	if e != nil {
		a.adminResult(w, r, e)
		return
	}
	cfg, e := a.Q.GetSAMLConfig(r.Context(), c.ID)
	if e != nil {
		a.serverError(w, r, e)
		return
	}
	if cfg.Revision != row.Revision {
		a.fail(w, r, 409, "Application settings changed. Start again.")
		return
	}
	v, signedIn := a.user(r)
	fresh := signedIn
	if signedIn && req.Force {
		fresh, e = a.samlFresh(r, a.Q, v.Session, row.TokenHash)
		if e != nil {
			a.serverError(w, r, e)
			return
		}
	}
	if req.Error == "" && !fresh && !req.Passive {
		dest := "/login?r=" + url.QueryEscape(r.URL.RequestURI())
		if req.Force {
			dest += "&prompt=login"
		}
		http.Redirect(w, r, dest, 303)
		return
	}
	// Firefox sends Origin: null for form POSTs under no-referrer. Keep the
	// same-origin CSRF check intact while suppressing cross-origin referrers.
	w.Header().Set("Referrer-Policy", "same-origin")
	// The issuance endpoint repeats all checks, including passive and forced login.
	a.page(w, r, "Continue to "+c.Name, `<p>Continue to {{.Data.Name}}.</p><form id="saml-continue" method="post" action="{{.Data.Action}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="t" value="{{.Data.Token}}"><button>Continue</button></form><script nonce="{{.Data.Nonce}}">document.getElementById('saml-continue').submit()</script>`, map[string]any{"Name": c.Name, "Action": "/saml/" + c.Slug + "/issue", "Token": r.URL.Query().Get("t"), "Nonce": samlCSP(w, "'self'")})
}
func samlCSP(w http.ResponseWriter, action string) string {
	nonce := security.Token()
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; script-src 'nonce-"+nonce+"'; form-action "+action+"; base-uri 'none'; frame-ancestors 'none'")
	return nonce
}
func (a *App) samlIssue(w http.ResponseWriter, r *http.Request) {
	c, ok := a.samlClient(w, r, false)
	if !ok {
		return
	}
	var response []byte
	var req samlidp.Request
	e := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		// Existing admin mutations use client then user; session deletion locks users.
		locked, e := q.LockClient(r.Context(), c.ID)
		if e != nil {
			return e
		}
		if locked.Disabled || locked.DeletedAt != nil {
			return adminError{403, "Application unavailable."}
		}
		c = locked
		row, pending, e := a.samlPending(r, c, q, true)
		if e != nil {
			return e
		}
		req = pending
		cfg, e := q.GetSAMLConfig(r.Context(), c.ID)
		if e != nil {
			return e
		}
		if row.Revision != cfg.Revision {
			return adminError{409, "Application settings changed. Start again."}
		}
		in := samlidp.ResponseInput{Issuer: a.samlBase(c) + "/metadata", Audience: cfg.EntityID, Request: req, Now: time.Now().UTC(), Error: req.Error}
		var actor *identity
		var uid *ids.UserID
		var sid *ids.SessionID
		if v, ok := a.user(r); ok {
			if _, e = q.LockUser(r.Context(), v.User.ID); e != nil {
				return e
			}
			if _, e = q.LockSession(r.Context(), v.Session.ID); e != nil && !notFound(e) {
				return e
			}
			actor, e = a.sessionByID(r.Context(), q, v.Session.ID)
			if e != nil {
				return e
			}
		}
		if actor == nil && in.Error == "" {
			if req.Passive {
				in.Error = "NoPassive"
			} else {
				return adminError{403, "Sign in again to continue."}
			}
		}
		if actor != nil {
			uid = &actor.User.ID
			sid = &actor.Session.ID
			fresh, e := a.samlFresh(r, q, actor.Session, row.TokenHash)
			if e != nil {
				return e
			}
			if req.Force && !fresh && in.Error == "" {
				if req.Passive {
					in.Error = "NoPassive"
				} else {
					return adminError{403, "Fresh authentication required."}
				}
			}
		}
		if in.Error == "" {
			if e = q.LockSAMLPolicy(r.Context()); e != nil {
				return e
			}
			allowed, e := a.permitted(r.Context(), q, c.ID, actor.User.ID)
			if e != nil {
				return e
			}
			if !allowed {
				in.Error = "RequestDenied"
			} else {
				subject, e := q.GetSAMLSubject(r.Context(), db.GetSAMLSubjectParams{ClientID: c.ID, UserID: actor.User.ID})
				if notFound(e) && req.AllowCreate {
					subject, e = q.CreateSAMLSubject(r.Context(), db.CreateSAMLSubjectParams{ClientID: c.ID, UserID: actor.User.ID, Subject: security.Token()})
				}
				if notFound(e) {
					if cfg.NameIDFormat == samlidp.Persistent {
						in.Error = "InvalidNameIDPolicy"
					}
				} else if e != nil {
					return e
				}
				in.Subject = subject
				if cfg.NameIDFormat == samlidp.Email {
					if !validEmail(actor.User.Email) {
						in.Error = "InvalidNameIDPolicy"
					} else {
						matches, e := q.UsersByEmail(r.Context(), actor.User.Email)
						if e != nil {
							return e
						}
						if len(matches) != 1 || matches[0].ID != actor.User.ID {
							in.Error = "InvalidNameIDPolicy"
						}
						in.Subject = actor.User.Email
					}
				}
				session, e := q.SAMLSession(r.Context(), db.SAMLSessionParams{ClientID: c.ID, SessionID: actor.Session.ID, SessionIndex: security.Token()})
				if e != nil {
					return e
				}
				in.SessionIndex = session.SessionIndex
				// AuthnInstant is completion of authentication to Guard, including MFA.
				// It does not claim to know when an upstream provider authenticated.
				in.AuthTime = actor.Session.CreatedAt
				in.SessionExpiry = minTime(actor.Session.ExpiresAt, in.Now.Add(time.Duration(c.SessionLifetimeS)*time.Second))
				in.Attributes = map[string][]string{}
				var mapping map[string]string
				if e = json.Unmarshal(cfg.Attributes, &mapping); e != nil {
					return e
				}
				for source, name := range mapping {
					switch source {
					case "uid":
						in.Attributes[name] = []string{subject}
					case "username":
						in.Attributes[name] = []string{actor.User.Username}
					case "email":
						in.Attributes[name] = []string{actor.User.Email}
					case "groups":
						members, e := q.GroupMembersByUserId(r.Context(), actor.User.ID)
						if e != nil {
							return e
						}
						for _, m := range members {
							g, e := q.GetGroup(r.Context(), m.GroupID)
							if e != nil {
								return e
							}
							if g.DeletedAt == nil {
								in.Attributes[name] = append(in.Attributes[name], g.Name)
							}
						}
						sort.Strings(in.Attributes[name])
					}
				}
			}
		}
		in.Now = time.Now().UTC()
		if !row.ExpiresAt.After(in.Now) {
			return adminError{410, "SAML request expired. Start again."}
		}
		if in.Error == "" {
			if actor == nil || !actor.Session.ExpiresAt.After(in.Now) {
				return adminError{403, "Sign in again to continue."}
			}
			in.SessionExpiry = minTime(actor.Session.ExpiresAt, in.Now.Add(time.Duration(c.SessionLifetimeS)*time.Second))
		}
		key, cert, e := a.samlSigningKey(r.Context(), q, c.ID)
		if e != nil {
			return e
		}
		response, e = samlidp.Response(in, key, cert)
		if e != nil {
			return e
		}
		if e = q.ConsumeSAMLRequest(r.Context(), row.ID); e != nil {
			return e
		}
		if c.DetailedLogging {
			decision := "success"
			if in.Error != "" {
				decision = in.Error
			}
			_, e = a.persistAccess(r.Context(), q, c, uid, sid, "request", "saml:"+fmt.Sprint(row.ID), map[string]any{"endpoint": "/saml/issue", "decision": decision})
		}
		return e
	})
	if e != nil {
		a.samlFailure(r, c, "issuance_failed")
		a.adminResult(w, r, e)
		return
	}
	action, _ := url.Parse(req.ACS)
	nonce := samlCSP(w, action.Scheme+"://"+action.Host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := template.Must(template.New("post").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Continue to application</title></head><body><form id="saml-response" method="post" action="{{.ACS}}"><input type="hidden" name="SAMLResponse" value="{{.Response}}"><input type="hidden" name="RelayState" value="{{.Relay}}"><button>Continue</button></form><script nonce="{{.Nonce}}">document.getElementById('saml-response').submit()</script></body></html>`))
	t.Execute(w, map[string]string{"ACS": req.ACS, "Response": base64.StdEncoding.EncodeToString(response), "Relay": req.RelayState, "Nonce": nonce})
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (a *App) samlFresh(r *http.Request, q *db.Queries, session db.Session, hash string) (bool, error) {
	return q.HasSAMLAuthentication(r.Context(), db.HasSAMLAuthenticationParams{SessionID: session.ID, RequestHash: hash})
}

// Only an explicitly forced login started for a live, browser-bound SAML
// continuation may produce proof. Ordinary/pre-existing login flows cannot.
func (a *App) samlLoginBinding(r *http.Request) (string, error) {
	target, e := url.Parse(r.URL.Query().Get("r"))
	if e != nil || target.IsAbs() || target.Host != "" || !strings.HasPrefix(target.Path, "/saml/") || !strings.HasSuffix(target.Path, "/continue") {
		return "", nil
	}
	row, e := a.Q.GetSAMLRequest(r.Context(), security.Hash(target.Query().Get("t")))
	if e != nil {
		return "", e
	}
	if !row.ExpiresAt.After(time.Now()) || row.ConsumedAt != nil || !security.Equal(row.BrowserHash, security.Hash(cookieValue(r, "saml_browser"))) {
		return "", adminError{403, "Invalid SAML login continuation."}
	}
	c, e := a.Q.GetClient(r.Context(), row.ClientID)
	if e != nil {
		return "", e
	}
	if target.Path != "/saml/"+c.Slug+"/continue" || c.Disabled || c.DeletedAt != nil {
		return "", adminError{403, "Invalid SAML login continuation."}
	}
	return row.TokenHash, nil
}

// Failure journals contain bounded reason codes only, never the protocol query.
func (a *App) samlFailure(r *http.Request, c db.Client, reason string) {
	if !c.DetailedLogging {
		return
	}
	var uid *ids.UserID
	var sid *ids.SessionID
	if v, ok := a.user(r); ok {
		uid = &v.User.ID
		sid = &v.Session.ID
	}
	if _, e := a.persistAccess(r.Context(), a.Q, c, uid, sid, "request", "saml-failure:"+security.Token(), map[string]any{"endpoint": r.URL.Path, "decision": reason}); e != nil {
		slog.Error("SAML failure journal unavailable", "client_id", c.ID, "reason", reason)
	}
}
