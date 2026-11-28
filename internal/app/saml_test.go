package app

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/crewjam/saml"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/samlidp"
	"github.com/le0developer/guard/internal/security"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSAMLConfigurationAndMetadata(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	c, e := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "SAML", Slug: "saml-app", ClientType: "Saml", ClientID: "saml", ClientSecret: "unused", SessionLifetimeS: 3600})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Q.SaveSAMLConfig(ctx, db.SaveSAMLConfigParams{ClientID: c.ID, EntityID: "https://sp", NameIDFormat: samlidp.Persistent}); e != nil {
		t.Fatal(e)
	}
	if e = a.Q.CreateSAMLACS(ctx, db.CreateSAMLACSParams{ClientID: c.ID, Url: "https://sp/acs", IsDefault: true}); e != nil {
		t.Fatal(e)
	}
	if e = a.createSAMLKey(ctx, a.Q, c.ID); e != nil {
		t.Fatal(e)
	}
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/saml/saml-app/metadata", nil))
	if rr.Code != 200 {
		t.Fatalf("metadata: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSAMLAdminRoutes(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "saml-admin", Role: "Admin", WebauthnUserID: []byte("saml-admin")})
	if e != nil {
		t.Fatal(e)
	}
	c, e := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "SAML", Slug: "admin-saml", ClientType: "Saml", ClientID: "saml-admin", ClientSecret: "unused", SessionLifetimeS: 3600})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", fmt.Sprintf("/admin/clients/%d/saml", c.ID), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: u}))
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Application identifier (Entity ID)") {
		t.Fatalf("admin %d %s", w.Code, w.Body.String())
	}
}

func samlFixture(t *testing.T) (*App, db.Client, *http.Cookie) {
	t.Helper()
	a := testApp(t)
	ctx := context.Background()
	c, e := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "SAML", Slug: "flow", ClientType: "Saml", ClientID: "flow", ClientSecret: "unused", SessionLifetimeS: 3600, DetailedLogging: true})
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.Q.SaveSAMLConfig(ctx, db.SaveSAMLConfigParams{ClientID: c.ID, EntityID: "https://sp", NameIDFormat: samlidp.Persistent})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Q.CreateSAMLACS(ctx, db.CreateSAMLACSParams{ClientID: c.ID, Url: "https://sp/acs", IsDefault: true}); e != nil {
		t.Fatal(e)
	}
	if e = a.createSAMLKey(ctx, a.Q, c.ID); e != nil {
		t.Fatal(e)
	}
	u, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "alice", Role: "User", Email: "alice@example.com", WebauthnUserID: []byte("alice")})
	if e != nil {
		t.Fatal(e)
	}
	token := security.Token()
	_, e = a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash(token), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	return a, c, &http.Cookie{Name: "session", Value: token}
}
func samlRequestURL(a *App, c db.Client, id, extra string) string {
	var b bytes.Buffer
	z, _ := flate.NewWriter(&b, 9)
	fmt.Fprintf(z, `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s/sso" %s><s:Issuer>https://sp</s:Issuer><p:NameIDPolicy AllowCreate="true"/></p:AuthnRequest>`, id, time.Now().UTC().Format(time.RFC3339Nano), a.samlBase(c), extra)
	z.Close()
	return "/saml/" + c.Slug + "/sso?" + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(b.Bytes())}, "RelayState": {"opaque-state"}}.Encode()
}
func samlHTTP(h http.Handler, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func samlCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
func samlField(w *httptest.ResponseRecorder, name string) string {
	m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(w.Body.String())
	if len(m) < 2 {
		return ""
	}
	return html.UnescapeString(m[1])
}
func TestSAMLFlowAndReplay(t *testing.T) {
	a, c, session := samlFixture(t)
	ctx := context.Background()
	sr, e := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
	if e != nil {
		t.Fatal(e)
	}
	g, e := a.Q.CreateGroup(ctx, db.CreateGroupParams{Name: "staff"})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Q.AdminAddMember(ctx, db.AdminAddMemberParams{GroupID: g.ID, UserID: sr.UserID}); e != nil {
		t.Fatal(e)
	}
	h := a.Handler()
	start := samlHTTP(h, "GET", samlRequestURL(a, c, "_flow", ""), nil, session)
	if start.Code != 303 {
		t.Fatalf("start %d %s", start.Code, start.Body.String())
	}
	browser := samlCookie(start, "saml_browser")
	path := start.Header().Get("Location")
	cont := samlHTTP(h, "GET", path, nil, session, browser)
	if cont.Code != 200 {
		t.Fatalf("continue %d %s", cont.Code, cont.Body.String())
	}
	token := samlField(cont, "t")
	form := url.Values{"t": {token}, "csrf_token": {samlField(cont, "csrf_token")}}
	post := "/saml/flow/issue"
	out := samlHTTP(h, "POST", post, form, session, browser)
	if out.Code != 200 {
		t.Fatalf("issue %d %s", out.Code, out.Body.String())
	}
	raw, e := base64.StdEncoding.DecodeString(samlField(out, "SAMLResponse"))
	if e != nil {
		t.Fatal(e)
	}
	metadata := samlHTTP(h, "GET", "/saml/flow/metadata", nil)
	var m saml.EntityDescriptor
	if e = xml.Unmarshal(metadata.Body.Bytes(), &m); e != nil {
		t.Fatal(e)
	}
	acs, _ := url.Parse("https://sp/acs")
	sp := saml.ServiceProvider{EntityID: "https://sp", AcsURL: *acs, IDPMetadata: &m}
	assertion, e := sp.ParseXMLResponse(raw, []string{"_flow"}, *acs)
	if e != nil {
		t.Fatal(e)
	}
	values := map[string][]string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, v := range attribute.Values {
				values[attribute.Name] = append(values[attribute.Name], v.Value)
			}
		}
	}
	for name, want := range map[string]string{"uid": a.oidcSubject(c, sr.UserID), "username": "alice", "email": "alice@example.com", "groups": "staff"} {
		if len(values[name]) != 1 || values[name][0] != want {
			t.Fatalf("fixed attribute %s: %v", name, values[name])
		}
	}
	if assertion.Subject.NameID.Value == "" || samlField(out, "RelayState") != "opaque-state" {
		t.Fatal("identity or relay lost")
	}
	if replay := samlHTTP(h, "POST", post, form, session, browser); replay.Code != 409 {
		t.Fatalf("replay %d", replay.Code)
	}
	fresh, e := New(a.Pool, a.Config)
	if e != nil {
		t.Fatal(e)
	}
	if replay := samlHTTP(fresh.Handler(), "GET", samlRequestURL(a, c, "_flow", ""), nil, session, browser); replay.Code != 409 {
		t.Fatalf("restart replay %d", replay.Code)
	}
}
func TestSAMLConcurrentIssuance(t *testing.T) {
	a, c, session := samlFixture(t)
	h := a.Handler()
	start := samlHTTP(h, "GET", samlRequestURL(a, c, "_race", ""), nil, session)
	browser := samlCookie(start, "saml_browser")
	cont := samlHTTP(h, "GET", start.Header().Get("Location"), nil, session, browser)
	form := url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}
	ch := make(chan int, 2)
	for range 2 {
		go func() { ch <- samlHTTP(h, "POST", "/saml/flow/issue", form, session, browser).Code }()
	}
	codes := []int{<-ch, <-ch}
	sort.Ints(codes)
	if codes[0] != 200 || codes[1] != 409 {
		t.Fatalf("issuance %v", codes)
	}
}
func TestSAMLBrowserBindingAndPassive(t *testing.T) {
	a, c, session := samlFixture(t)
	h := a.Handler()
	start := samlHTTP(h, "GET", samlRequestURL(a, c, "_passive", `IsPassive="true"`), nil)
	browser := samlCookie(start, "saml_browser")
	path := start.Header().Get("Location")
	if other := samlHTTP(h, "GET", path, nil, session); other.Code != 403 {
		t.Fatalf("other browser %d", other.Code)
	}
	cont := samlHTTP(h, "GET", path, nil, browser)
	if cont.Code != 200 {
		t.Fatalf("passive %d", cont.Code)
	}
	out := samlHTTP(h, "POST", "/saml/flow/issue", url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}, browser)
	raw, _ := base64.StdEncoding.DecodeString(samlField(out, "SAMLResponse"))
	if out.Code != 200 || !bytes.Contains(raw, []byte("NoPassive")) || bytes.Contains(raw, []byte("saml:Assertion")) {
		t.Fatalf("passive response %d %s", out.Code, raw)
	}
}

func TestSAMLForceAuthnRejectsUnrelatedNewSession(t *testing.T) {
	a, c, old := samlFixture(t)
	h := a.Handler()
	start := samlHTTP(h, "GET", samlRequestURL(a, c, "_force", `ForceAuthn="true"`), nil, old)
	browser := samlCookie(start, "saml_browser")
	oldRow, e := a.Q.SessionByTokenHash(context.Background(), security.Hash(old.Value))
	if e != nil {
		t.Fatal(e)
	}
	raw := security.Token()
	_, e = a.Q.CreateSession(context.Background(), db.CreateSessionParams{UserID: oldRow.UserID, TokenHash: security.Hash(raw), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	cont := samlHTTP(h, "GET", start.Header().Get("Location"), nil, &http.Cookie{Name: "session", Value: raw}, browser)
	if cont.Code != 303 || !strings.Contains(cont.Header().Get("Location"), "prompt=login") {
		t.Fatalf("unrelated session satisfied forced login: %d %s", cont.Code, cont.Body.String())
	}
}

func TestSAMLForcedPasswordLogin(t *testing.T) {
	a, c, old := samlFixture(t)
	ctx := context.Background()
	s, e := a.Q.SessionByTokenHash(ctx, security.Hash(old.Value))
	if e != nil {
		t.Fatal(e)
	}
	u, e := a.Q.GetUser(ctx, s.UserID)
	if e != nil {
		t.Fatal(e)
	}
	p := adminUserParams(u)
	p.Password, e = security.HashPassword("saml-test-password")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Q.UpdateUser(ctx, p); e != nil {
		t.Fatal(e)
	}
	h := a.Handler()
	start := samlHTTP(h, "GET", samlRequestURL(a, c, "_forcedpassword", `ForceAuthn="true"`), nil, old)
	browser := samlCookie(start, "saml_browser")
	continuation := start.Header().Get("Location")
	cont := samlHTTP(h, "GET", continuation, nil, old, browser)
	if cont.Code != 303 {
		t.Fatalf("force redirect %d", cont.Code)
	}
	login := samlHTTP(h, "GET", cont.Header().Get("Location"), nil, old, browser)
	if login.Code != 200 {
		t.Fatalf("login %d %s", login.Code, login.Body.String())
	}
	lc := samlCookie(login, "login_session")
	row, e := a.Q.LoginSessionByTokenHash(ctx, security.Hash(lc.Value))
	if e != nil {
		t.Fatal(e)
	}
	completed := samlHTTP(h, "POST", "/login/password", url.Values{"email": {"alice"}, "password": {"saml-test-password"}, "login_token": {row.InternalToken}, "csrf_token": {samlField(login, "csrf_token")}}, old, browser, lc)
	if completed.Code != 303 {
		t.Fatalf("complete login %d %s", completed.Code, completed.Body.String())
	}
	session := samlCookie(completed, "session")
	cont = samlHTTP(h, "GET", continuation, nil, session, browser)
	if cont.Code != 200 {
		t.Fatalf("post-auth continuation %d %s", cont.Code, cont.Body.String())
	}
	out := samlHTTP(h, "POST", "/saml/flow/issue", url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}, session, browser)
	if out.Code != 200 || samlField(out, "SAMLResponse") == "" {
		t.Fatalf("forced issuance %d %s", out.Code, out.Body.String())
	}
}
func TestSAMLConfigurationChangeAndRevocation(t *testing.T) {
	for _, change := range []string{"settings", "logout", "disabled", "expiry"} {
		t.Run(change, func(t *testing.T) {
			a, c, session := samlFixture(t)
			h := a.Handler()
			start := samlHTTP(h, "GET", samlRequestURL(a, c, "_changed", ""), nil, session)
			browser := samlCookie(start, "saml_browser")
			cont := samlHTTP(h, "GET", start.Header().Get("Location"), nil, session, browser)
			form := url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}
			ctx := context.Background()
			switch change {
			case "settings":
				if e := a.Q.BumpSAMLRevision(ctx, c.ID); e != nil {
					t.Fatal(e)
				}
			case "logout":
				s, e := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
				if e != nil {
					t.Fatal(e)
				}
				if e = a.Q.DeleteSession(ctx, s.ID); e != nil {
					t.Fatal(e)
				}
			case "disabled":
				if _, e := a.Q.SetClientDisabled(ctx, db.SetClientDisabledParams{ID: c.ID, Disabled: true}); e != nil {
					t.Fatal(e)
				}
			case "expiry":
				if _, e := a.Pool.Exec(ctx, "UPDATE saml_requests SET expires_at=now()-interval '1 second'"); e != nil {
					t.Fatal(e)
				}
			}
			out := samlHTTP(h, "POST", "/saml/flow/issue", form, session, browser)
			if out.Code == 200 && samlField(out, "SAMLResponse") != "" {
				t.Fatal("issued after " + change)
			}
		})
	}
}
func TestSAMLAdminSaveKeepsSingleCertificate(t *testing.T) {
	a, c, session := samlFixture(t)
	ctx := context.Background()
	s, e := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
	if e != nil {
		t.Fatal(e)
	}
	u, e := a.Q.GetUser(ctx, s.UserID)
	if e != nil {
		t.Fatal(e)
	}
	u.Role = "Admin"
	mux := http.NewServeMux()
	a.registerAdmin(mux)
	request := func(path string, form url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: u}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	path := samlAdminPath(c.ID)
	form := url.Values{"entity_id": {"https://sp"}, "name_id_format": {samlidp.Persistent}, "acs": {"0 https://sp/acs\n1 https://sp/second"}, "default_index": {"1"}, "launch_url": {"https://sp/login"}}
	if out := request(path, form); out.Code != 303 {
		t.Fatalf("save %d %s", out.Code, out.Body.String())
	}
	keys, e := a.Q.SAMLKeys(ctx, c.ID)
	if e != nil || len(keys) != 1 {
		t.Fatalf("want one certificate: %d %v", len(keys), e)
	}
	logs, auditErr := a.Q.AdminAuditPage(ctx, 1<<63-1)
	if auditErr != nil || len(logs) == 0 {
		t.Fatalf("audit: %v", auditErr)
	}
	var auditData map[string]any
	if err := json.Unmarshal(logs[0].Data, &auditData); err != nil {
		t.Fatal(err)
	}
	changes, ok := auditData["changes"].(map[string]any)
	if !ok || changes["saml"].(map[string]any)["before"].(map[string]any)["launch_url"] != "" || changes["saml"].(map[string]any)["after"].(map[string]any)["launch_url"] != "https://sp/login" {
		t.Fatalf("missing SAML diff: %#v", auditData)
	}
	if changes["saml_acs.1"].(map[string]any)["after"].(map[string]any)["url"] != "https://sp/second" {
		t.Fatal("new ACS missing")
	}
	if strings.Contains(string(logs[0].Data), keys[0].PrivateKey) {
		t.Fatal("SAML private key leaked")
	}
	original := append([]byte(nil), keys[0].Certificate...)
	if out := request(path, form); out.Code != 303 {
		t.Fatalf("save again %d %s", out.Code, out.Body.String())
	}
	logs, auditErr = a.Q.AdminAuditPage(ctx, 1<<63-1)
	if auditErr != nil {
		t.Fatal(auditErr)
	}
	if err := json.Unmarshal(logs[0].Data, &auditData); err != nil {
		t.Fatal(err)
	}
	if auditData["outcome"] != "unchanged" || len(auditData["changes"].(map[string]any)) != 0 {
		t.Fatalf("identical SAML save invented changes: %#v", auditData)
	}
	keys, e = a.Q.SAMLKeys(ctx, c.ID)
	if e != nil || len(keys) != 1 || !bytes.Equal(original, keys[0].Certificate) {
		t.Fatal("saving changed the certificate")
	}
	if out := request(path+"/keys/prepare", nil); out.Code != 404 {
		t.Fatalf("rotation still exposed: %d", out.Code)
	}
	form.Set("acs", "0 https://evil/acs\n0 https://sp/acs")
	if out := request(path, form); out.Code != 422 {
		t.Fatalf("duplicate ACS %d", out.Code)
	}
	form.Set("acs", "0 https://sp/acs")
	form.Set("default_index", "0")
	form.Set("require_signature", "on")
	if out := request(path, form); out.Code != 422 {
		t.Fatalf("missing SP cert %d", out.Code)
	}
	r := httptest.NewRequest("GET", fmt.Sprintf("/admin/clients/%d", c.ID), nil)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, &identity{User: u}))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Show client secret") || !strings.Contains(w.Body.String(), "Group access rules") {
		t.Fatalf("SAML client page %d %s", w.Code, w.Body.String())
	}
}

func samlChangeRequestXML(path, old, new string) string {
	u, _ := url.Parse(path)
	q := u.Query()
	b, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	z := flate.NewReader(bytes.NewReader(b))
	raw, _ := io.ReadAll(z)
	z.Close()
	var out bytes.Buffer
	enc, _ := flate.NewWriter(&out, 9)
	enc.Write([]byte(strings.Replace(string(raw), old, new, 1)))
	enc.Close()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(out.Bytes()))
	u.RawQuery = q.Encode()
	return u.String()
}
func TestSAMLEmailNameIDWithoutCreatingPersistentMapping(t *testing.T) {
	a, c, session := samlFixture(t)
	ctx := context.Background()
	_, e := a.Q.SaveSAMLConfig(ctx, db.SaveSAMLConfigParams{ClientID: c.ID, EntityID: "https://sp", NameIDFormat: samlidp.Email})
	if e != nil {
		t.Fatal(e)
	}
	h := a.Handler()
	path := samlChangeRequestXML(samlRequestURL(a, c, "_email", ""), `AllowCreate="true"`, `AllowCreate="false"`)
	start := samlHTTP(h, "GET", path, nil, session)
	browser := samlCookie(start, "saml_browser")
	cont := samlHTTP(h, "GET", start.Header().Get("Location"), nil, session, browser)
	out := samlHTTP(h, "POST", "/saml/flow/issue", url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}, session, browser)
	raw, _ := base64.StdEncoding.DecodeString(samlField(out, "SAMLResponse"))
	if out.Code != 200 || !bytes.Contains(raw, []byte("alice@example.com")) {
		t.Fatalf("email response %d %s", out.Code, raw)
	}
	sr, e := a.Q.SessionByTokenHash(ctx, security.Hash(session.Value))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Q.GetSAMLSubject(ctx, db.GetSAMLSubjectParams{ClientID: c.ID, UserID: sr.UserID}); !notFound(e) {
		t.Fatalf("created persistent subject despite AllowCreate=false: %v", e)
	}
	firstUID := samlUIDFromResponse(t, raw)
	start = samlHTTP(h, "GET", samlRequestURL(a, c, "_emailcreate", ""), nil, session, browser)
	cont = samlHTTP(h, "GET", start.Header().Get("Location"), nil, session, browser)
	out = samlHTTP(h, "POST", "/saml/flow/issue", url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}, session, browser)
	raw, _ = base64.StdEncoding.DecodeString(samlField(out, "SAMLResponse"))
	if out.Code != 200 || firstUID == "" || samlUIDFromResponse(t, raw) != firstUID {
		t.Fatal("uid changed after creating a persistent mapping")
	}

}
func TestSAMLFailureJournalAndCapacity(t *testing.T) {
	a, c, session := samlFixture(t)
	ctx := context.Background()
	h := a.Handler()
	out := samlHTTP(h, "GET", "/saml/flow/sso?SAMLRequest=bad&RelayState=secret-relay", nil, session)
	if out.Code != 400 {
		t.Fatalf("invalid %d", out.Code)
	}
	logs, e := a.Q.AccessLogsByClientId(ctx, c.ID)
	if e != nil || len(logs) != 1 {
		t.Fatalf("journal %d %v", len(logs), e)
	}
	if bytes.Contains(logs[0].Data, []byte("secret-relay")) || !bytes.Contains(logs[0].Data, []byte("invalid_request")) {
		t.Fatal("failure journal contains state or lacks reason")
	}
	_, e = a.Pool.Exec(ctx, `INSERT INTO saml_requests(client_id,request_id,token_hash,browser_hash,revision,request,expires_at) SELECT $1,'_cap'||n,'cap-token'||n,'browser'||n,1,'{}',now()+interval '10 minutes' FROM generate_series(1,500) n`, c.ID)
	if e != nil {
		t.Fatal(e)
	}
	out = samlHTTP(h, "GET", samlRequestURL(a, c, "_capacity", ""), nil, session)
	if out.Code != 429 {
		t.Fatalf("client cap %d %s", out.Code, out.Body.String())
	}
	if _, e = a.Pool.Exec(ctx, `UPDATE saml_requests SET consumed_at=now() WHERE client_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	out = samlHTTP(h, "GET", samlRequestURL(a, c, "_afterconsumption", ""), nil, session)
	if out.Code != 303 {
		t.Fatalf("consumed reservations count as pending: %d %s", out.Code, out.Body.String())
	}
}

func TestSAMLUnsupportedContextReturnsSignedErrorWithoutForcedLogin(t *testing.T) {
	a, c, session := samlFixture(t)
	h := a.Handler()
	path := samlChangeRequestXML(samlRequestURL(a, c, "_context", `ForceAuthn="true"`), `</p:AuthnRequest>`, `<p:RequestedAuthnContext><s:AuthnContextClassRef>unsupported</s:AuthnContextClassRef></p:RequestedAuthnContext></p:AuthnRequest>`)
	start := samlHTTP(h, "GET", path, nil, session)
	browser := samlCookie(start, "saml_browser")
	cont := samlHTTP(h, "GET", start.Header().Get("Location"), nil, session, browser)
	out := samlHTTP(h, "POST", "/saml/flow/issue", url.Values{"t": {samlField(cont, "t")}, "csrf_token": {samlField(cont, "csrf_token")}}, session, browser)
	raw, _ := base64.StdEncoding.DecodeString(samlField(out, "SAMLResponse"))
	if out.Code != 200 || !bytes.Contains(raw, []byte("NoAuthnContext")) {
		t.Fatalf("context error %d %s", out.Code, out.Body.String())
	}
}

func TestSAMLHasNoAttributeOrRotationSettings(t *testing.T) {
	r := httptest.NewRequest("GET", "/admin/clients/1/saml", nil)
	w := httptest.NewRecorder()
	(&App{}).page(w, r, "SAML configuration", adminSAMLTemplate, map[string]any{"Client": db.Client{ID: 1}, "Config": db.SamlClientConfig{}, "Action": "/admin/clients/1/saml"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, old := range []string{"attribute_", "Released attributes", "Prepare next", "overlap", "expires"} {
		if strings.Contains(w.Body.String(), old) {
			t.Fatalf("obsolete setting remains: %s", old)
		}
	}
}
func TestSAMLClientAutomaticallyGetsOneCertificate(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "admin-auto", Role: "Admin", WebauthnUserID: []byte("auto")})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "/admin/clients", strings.NewReader(url.Values{"name": {"Auto SAML"}, "client_type": {"Saml"}, "session_lifetime_s": {"3600"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	w := httptest.NewRecorder()
	if e = a.adminWriteClient(w, r, &identity{User: u}); e != nil {
		t.Fatal(e)
	}
	clients, e := a.Q.ListClients(ctx)
	if e != nil || len(clients) != 1 {
		t.Fatalf("clients %v %v", clients, e)
	}
	keys, e := a.Q.SAMLKeys(ctx, clients[0].ID)
	if e != nil || len(keys) != 1 {
		t.Fatalf("automatic certificate: %d %v", len(keys), e)
	}
	cert, e := x509.ParseCertificate(keys[0].Certificate)
	if e != nil || cert.NotAfter.Year() != 9999 {
		t.Fatalf("unexpected expiry %v %v", cert, e)
	}
}

func TestSAMLUpgradePreservesCurrentCertificate(t *testing.T) {
	a, c, _ := samlFixture(t)
	ctx := context.Background()
	keys, e := a.Q.SAMLKeys(ctx, c.ID)
	if e != nil || len(keys) != 1 {
		t.Fatal(e)
	}
	original := keys[0]
	// Reconstruct the previous lifecycle columns, then exercise the upgrade with
	// an active certificate and an unused next certificate in the same client.
	_, e = a.Pool.Exec(ctx, `ALTER TABLE saml_signing_keys DROP CONSTRAINT saml_signing_keys_client_id_key;
 ALTER TABLE saml_signing_keys ADD state text NOT NULL DEFAULT 'active',ADD expires_at timestamptz NOT NULL DEFAULT now(),ADD retire_at timestamptz,ADD retired_at timestamptz;
 ALTER TABLE saml_client_configs ADD attributes jsonb NOT NULL DEFAULT '{}', ADD key_overlap_s integer NOT NULL DEFAULT 604800;`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.Pool.Exec(ctx, `INSERT INTO saml_signing_keys(client_id,key_ref,private_key,certificate,state) VALUES($1,'unused-next','unused-secret',$2,'next')`, c.ID, []byte("unused-certificate"))
	if e != nil {
		t.Fatal(e)
	}
	migration, e := os.ReadFile("../db/migrations/011_saml_simplify.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Pool.Exec(ctx, string(migration)); e != nil {
		t.Fatal(e)
	}
	keys, e = a.Q.SAMLKeys(ctx, c.ID)
	if e != nil || len(keys) != 1 || !bytes.Equal(keys[0].Certificate, original.Certificate) || keys[0].PrivateKey != original.PrivateKey {
		t.Fatal("upgrade replaced the active signing identity")
	}
	if e = a.createSAMLKey(ctx, a.Q, c.ID); e != nil {
		t.Fatal(e)
	}
	keys, e = a.Q.SAMLKeys(ctx, c.ID)
	if e != nil || len(keys) != 1 || !bytes.Equal(keys[0].Certificate, original.Certificate) {
		t.Fatal("automatic generation replaced an existing certificate")
	}
}

func samlUIDFromResponse(t *testing.T, raw []byte) string {
	t.Helper()
	var r saml.Response
	if e := xml.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	if r.Assertion != nil {
		for _, statement := range r.Assertion.AttributeStatements {
			for _, attribute := range statement.Attributes {
				if attribute.Name == "uid" && len(attribute.Values) > 0 {
					return attribute.Values[0].Value
				}
			}
		}
	}
	return ""
}
