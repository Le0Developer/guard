package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func mfaTestUser(t *testing.T, a *App) db.User {
	t.Helper()
	u, e := a.Q.CreateUser(context.Background(), db.CreateUserParams{Username: "mfa-user", Role: "User", WebauthnUserID: []byte(mfaRandom())})
	if e != nil {
		t.Fatal(e)
	}
	return u
}
func mfaTestPending(t *testing.T, a *App, u db.User) (db.LoginSession, string, string) {
	t.Helper()
	ctx := context.Background()
	raw := mfaRandom()
	l, e := a.Q.CreateLoginSession(ctx, db.CreateLoginSessionParams{TokenHash: mfaHash(raw), InternalToken: mfaRandom(), RedirectUri: "/", State: []byte(`{}`), ExpiresAt: time.Now().Add(5 * time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	ticket, e := a.mfaTicket(ctx, a.Q, u, u.ID, nil, &l.ID, "login", mfaState{})
	if e != nil {
		t.Fatal(e)
	}
	return l, raw, ticket
}
func mfaTestRequest(raw, ticket, method, code string) *http.Request {
	r := httptest.NewRequest("POST", "/login/mfa", strings.NewReader(url.Values{"method": {method}, "code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "login_session", Value: raw})
	r.AddCookie(&http.Cookie{Name: "mfa_pending", Value: ticket})
	return r
}
func TestMFARecoveryConcurrentOneUse(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	_, e := a.Q.CreateRecoveryCode(ctx, db.CreateRecoveryCodeParams{UserID: u.ID, Hash: mfaRecoveryHash(u.ID, "backup-code")})
	if e != nil {
		t.Fatal(e)
	}
	_, r1, c1 := mfaTestPending(t, a, u)
	_, r2, c2 := mfaTestPending(t, a, u)
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for _, v := range [][2]string{{r1, c1}, {r2, c2}} {
		wg.Add(1)
		go func(v [2]string) {
			defer wg.Done()
			out := httptest.NewRecorder()
			a.mfaCode(out, mfaTestRequest(v[0], v[1], "recovery", "backup-code"))
			results <- out.Code
		}(v)
	}
	wg.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 303 {
			success++
		} else if status != 400 {
			t.Fatalf("unexpected %d", status)
		}
	}
	if success != 1 {
		t.Fatalf("successful uses %d", success)
	}
}
func TestMFATOTPReplayAndBrowserBinding(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	sealed, e := a.mfaSeal(u.ID, secret)
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.Q.CreateTotpAuthenticator(ctx, db.CreateTotpAuthenticatorParams{UserID: u.ID, Name: "phone", Secret: sealed, LastStep: -1})
	if e != nil {
		t.Fatal(e)
	}
	_, raw, ticket := mfaTestPending(t, a, u)
	code := mfaTOTP(secret, time.Now().Unix()/30)
	out := httptest.NewRecorder()
	a.mfaCode(out, mfaTestRequest("wrong-browser", ticket, "totp", code))
	if out.Code != 400 {
		t.Fatalf("accepted foreign browser %d", out.Code)
	}
	out = httptest.NewRecorder()
	a.mfaCode(out, mfaTestRequest(raw, ticket, "totp", code))
	if out.Code != 303 {
		t.Fatalf("first use %d %s", out.Code, out.Body.String())
	}
	_, raw, ticket = mfaTestPending(t, a, u)
	out = httptest.NewRecorder()
	a.mfaCode(out, mfaTestRequest(raw, ticket, "totp", code))
	if out.Code != 400 {
		t.Fatalf("accepted replay %d", out.Code)
	}
}
func TestMFACeremonyExpiryAndRevision(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	_, _, ticket := mfaTestPending(t, a, u)
	if e := a.Q.MFABumpRevision(ctx, u.ID); e != nil {
		t.Fatal(e)
	}
	if e := transaction(ctx, a.Pool, func(q *db.Queries) error { _, _, e := a.mfaLoad(ctx, q, ticket, "login"); return e }); e == nil {
		t.Fatal("accepted stale revision")
	}
	u, e := a.Q.GetUser(ctx, u.ID)
	if e != nil {
		t.Fatal(e)
	}
	_, _, ticket = mfaTestPending(t, a, u)
	if _, e = a.Pool.Exec(ctx, "UPDATE mfa_ceremonies SET expires_at=now()-interval '1 second' WHERE token_hash=$1", mfaHash(ticket)); e != nil {
		t.Fatal(e)
	}
	if e = transaction(ctx, a.Pool, func(q *db.Queries) error { _, _, e := a.mfaLoad(ctx, q, ticket, "login"); return e }); e == nil {
		t.Fatal("accepted expired ceremony")
	}
}
func TestMFAManagementAuthorizationAndRevocation(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	other, e := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "other", Role: "User", WebauthnUserID: []byte(mfaRandom())})
	if e != nil {
		t.Fatal(e)
	}
	s, e := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: mfaHash("first"), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	second, e := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: mfaHash("second"), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest("GET", "/security", nil)
	req = req.WithContext(context.WithValue(ctx, identityKey{}, &identity{u, s}))
	req.SetPathValue("id", fmt.Sprint(other.ID))
	if e = transaction(ctx, a.Pool, func(q *db.Queries) error { _, e := a.mfaContext(req, q); return e }); e == nil {
		t.Fatal("non-admin managed another account")
	}
	req.SetPathValue("id", "")
	if e = transaction(ctx, a.Pool, func(q *db.Queries) error {
		c, e := a.mfaContext(req, q)
		if e != nil {
			return e
		}
		return a.mfaChanged(ctx, q, c.Target, c.Actor.ID, c.keep(), "test")
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Q.GetSession(ctx, s.ID); e != nil {
		t.Fatal("owner initiating session revoked", e)
	}
	if _, e = a.Q.GetSession(ctx, second.ID); !notFound(e) {
		t.Fatal("other session survives", e)
	}
	if _, e = a.Pool.Exec(ctx, "UPDATE sessions SET created_at=now()-interval '6 minutes' WHERE id=$1", s.ID); e != nil {
		t.Fatal(e)
	}
	if e = transaction(ctx, a.Pool, func(q *db.Queries) error { _, e := a.mfaContext(req, q); return e }); e == nil {
		t.Fatal("old session changed security")
	}
}
func TestMFAWebEnrollmentPersistsBoundChallenge(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u := mfaTestUser(t, a)
	s, e := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: mfaHash("owner-session"), ExpiresAt: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	req := httptest.NewRequest("POST", "/security/keys/start", strings.NewReader(url.Values{"name": {"security key"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(ctx, identityKey{}, &identity{u, s}))
	out := httptest.NewRecorder()
	a.mfaEnrollStart(out, req)
	if out.Code != 200 {
		t.Fatalf("start %d %s", out.Code, out.Body.String())
	}
	var data struct {
		Ceremony  string `json:"ceremony"`
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if e = json.Unmarshal(out.Body.Bytes(), &data); e != nil {
		t.Fatal(e)
	}
	if data.Ceremony == "" || data.PublicKey.Challenge == "" {
		t.Fatal("missing client challenge", out.Body.String())
	}
	ticket, e := a.Q.MfaCeremonyByTokenHash(ctx, mfaHash(data.Ceremony))
	if e != nil {
		t.Fatal(e)
	}
	if ticket.SessionID == nil || *ticket.SessionID != s.ID || ticket.ActorID != u.ID || ticket.UserID != u.ID || ticket.Revision != u.MfaRevision || ticket.Purpose != "key-enroll" {
		t.Fatalf("unbound %+v", ticket)
	}
	req = httptest.NewRequest("POST", "/security/keys/finish", strings.NewReader(url.Values{"ceremony": {data.Ceremony}, "credential": {"{}"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(ctx, identityKey{}, &identity{u, s}))
	out = httptest.NewRecorder()
	a.mfaEnrollFinish(out, req)
	if out.Code != 400 {
		t.Fatalf("invalid credential %d", out.Code)
	}
	ticket, e = a.Q.GetMfaCeremony(ctx, ticket.ID)
	if e != nil {
		t.Fatal(e)
	}
	if ticket.Attempts != 1 {
		t.Fatalf("invalid attempt not persisted %+v", ticket)
	}
}
