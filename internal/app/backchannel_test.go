package app

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func logoutClaims(t *testing.T, a *App, c db.Client, raw string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT")
	}
	dec := func(s string) map[string]any {
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		if e = json.Unmarshal(b, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	head, claims := dec(parts[0]), dec(parts[1])
	keys, e := a.Q.SigningKeysByClientId(context.Background(), c.ID)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, k := range keys {
		if head["kid"] != fmtID(k.ID) {
			continue
		}
		private, e := x509.ParsePKCS1PrivateKey(k.Key)
		if e != nil {
			t.Fatal(e)
		}
		sig, e := base64.RawURLEncoding.DecodeString(parts[2])
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if e = rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, hash[:], sig); e != nil {
			t.Fatal(e)
		}
		found = true
	}
	if !found {
		t.Fatal("JWT key missing from provider keys")
	}
	return head, claims
}
func fmtID[T ~int64](id T) string { return strconv.FormatInt(int64(id), 10) }
func backchannelFixture(t *testing.T, endpoint string) (oauthFixture, map[string]any) {
	t.Helper()
	f := newOAuthFixture(t)
	c, e := f.a.Q.SetClientBackchannelLogout(context.Background(), db.SetClientBackchannelLogoutParams{ID: f.client.ID, BackchannelLogoutUri: endpoint, BackchannelLogoutSessionRequired: true})
	if e != nil {
		t.Fatal(e)
	}
	f.client = c
	code := f.code(t)
	status, tokens := f.post("/oauth2/token", oauthCodeFields(code))
	if status != 200 {
		t.Fatalf("tokens %d %v", status, tokens)
	}
	return f, tokens
}
func TestBackchannelSIDStableAndSignedDelivery(t *testing.T) {
	var status atomic.Int32
	status.Store(503)
	received := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.URL.RawQuery != "keep=value" {
			t.Error("incorrect logout request")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		received <- r.PostForm.Get("logout_token")
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()
	f, tokens := backchannelFixture(t, server.URL+"?keep=value")
	ctx := context.Background()
	_, first := logoutClaims(t, f.a, f.client, tokens["id_token"].(string))
	sid, ok := first["sid"].(string)
	if !ok || len(sid) < 40 {
		t.Fatalf("missing opaque sid %v", first)
	}
	code := f.code(t)
	httpStatus, newTokens := f.post("/oauth2/token", oauthCodeFields(code))
	if httpStatus != 200 {
		t.Fatal(newTokens)
	}
	_, again := logoutClaims(t, f.a, f.client, newTokens["id_token"].(string))
	if again["sid"] != sid {
		t.Fatal("same browser/client sid changed")
	}
	httpStatus, refreshed := f.post("/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	if httpStatus != 200 {
		t.Fatal(refreshed)
	}
	_, afterRefresh := logoutClaims(t, f.a, f.client, refreshed["id_token"].(string))
	if afterRefresh["sid"] != sid {
		t.Fatal("refresh changed sid")
	}
	if e := f.a.Q.DeleteSession(ctx, f.who.Session.ID); e != nil {
		t.Fatal(e)
	}
	rows, e := f.a.Q.ListLogoutDeliveries(ctx)
	if e != nil || len(rows) != 1 {
		t.Fatalf("not queued once %v %v", rows, e)
	}
	if e = f.a.deliverLogoutBatch(ctx); e != nil {
		t.Fatal(e)
	}
	raw := <-received
	head, claims := logoutClaims(t, f.a, f.client, raw)
	if head["typ"] != "logout+jwt" || head["alg"] != "RS256" || claims["sid"] != sid || claims["iss"] != f.a.oauthIssuer(f.client) || claims["aud"] != f.client.ClientID || claims["sub"] != f.a.oidcSubject(f.client, f.who.User.ID) || claims["jti"] == "" {
		t.Fatalf("wrong logout JWT %v %v", head, claims)
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("logout includes nonce")
	}
	if claims["exp"].(float64) <= claims["iat"].(float64) || claims["exp"].(float64) > float64(time.Now().Add(3*time.Minute).Unix()) {
		t.Fatal("incorrect token lifetime")
	}
	events, ok := claims["events"].(map[string]any)
	if !ok || events["http://schemas.openid.net/event/backchannel-logout"] == nil {
		t.Fatal("logout event absent")
	}
	d, e := f.a.Q.GetLogoutDelivery(ctx, rows[0].ID)
	if e != nil || d.Attempts != 1 || d.DeliveredAt != nil || !d.NextAttemptAt.After(time.Now()) {
		t.Fatalf("retry missing %v %v", d, e)
	}
	status.Store(204)
	_, e = f.a.Pool.Exec(ctx, "UPDATE logout_deliveries SET next_attempt_at=now() WHERE id=$1", d.ID)
	if e != nil {
		t.Fatal(e)
	}
	restarted, e := New(f.a.Pool, f.a.Config)
	if e != nil {
		t.Fatal(e)
	}
	if e = restarted.deliverLogoutBatch(ctx); e != nil {
		t.Fatal(e)
	}
	_, retry := logoutClaims(t, f.a, f.client, <-received)
	if retry["jti"] != claims["jti"] || retry["sid"] != sid {
		t.Fatal("retry changed event identity")
	}
	d, e = f.a.Q.GetLogoutDelivery(ctx, d.ID)
	if e != nil || d.DeliveredAt == nil || d.Attempts != 2 {
		t.Fatalf("not delivered %v %v", d, e)
	}
	if e = f.a.deliverLogoutBatch(ctx); e != nil {
		t.Fatal(e)
	}
	if len(received) != 0 {
		t.Fatal("delivered twice")
	}
}
func TestBackchannelDeletionPathsAndRollback(t *testing.T) {
	for _, mode := range []string{"user", "admin", "mfa", "expiry", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := backchannelFixture(t, "https://client.example/logout")
			ctx := context.Background()
			var e error
			switch mode {
			case "user":
				e = f.a.Q.DeleteSession(ctx, f.who.Session.ID)
			case "admin":
				e = f.a.Q.AdminDeleteUserSessions(ctx, f.who.User.ID)
			case "mfa":
				e = f.a.Q.MFARevokeSessions(ctx, db.MFARevokeSessionsParams{UserID: f.who.User.ID, KeepSession: ids.SessionID(0)})
			case "expiry":
				_, e = f.a.Q.UpdateSession(ctx, db.UpdateSessionParams{ID: f.who.Session.ID, UserID: f.who.User.ID, TokenHash: f.who.Session.TokenHash, ExpiresAt: time.Now().Add(-time.Second)})
				if e == nil {
					e = f.a.cleanup(ctx)
				}
			case "rollback":
				sentinel := errors.New("rollback")
				e = transaction(ctx, f.a.Pool, func(q *db.Queries) error {
					if err := q.DeleteSession(ctx, f.who.Session.ID); err != nil {
						return err
					}
					return sentinel
				})
				if !errors.Is(e, sentinel) {
					t.Fatal(e)
				}
				e = nil
			}
			if e != nil {
				t.Fatal(e)
			}
			rows, e := f.a.Q.ListLogoutDeliveries(ctx)
			want := 1
			if mode == "rollback" {
				want = 0
			}
			if e != nil || len(rows) != want {
				t.Fatalf("deliveries %v %v want%d", rows, e, want)
			}
		})
	}
}
func TestBackchannelNoRedirectsOrPermanentRetries(t *testing.T) {
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	for _, code := range []int{302, 400, 401, 404} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(code)
			}))
			defer server.Close()
			f, _ := backchannelFixture(t, server.URL)
			ctx := context.Background()
			if e := f.a.Q.DeleteSession(ctx, f.who.Session.ID); e != nil {
				t.Fatal(e)
			}
			if e := f.a.deliverLogoutBatch(ctx); e != nil {
				t.Fatal(e)
			}
			rows, e := f.a.Q.ListLogoutDeliveries(ctx)
			if e != nil || len(rows) != 1 || rows[0].CancelledAt == nil {
				t.Fatalf("permanent failure not cancelled %v %v", rows, e)
			}
			if e = f.a.deliverLogoutBatch(ctx); e != nil {
				t.Fatal(e)
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("logout JWT leaked through redirect")
	}
}
func TestBackchannelConcurrentWorkers(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(25 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer server.Close()
	f, _ := backchannelFixture(t, server.URL)
	ctx := context.Background()
	if e := f.a.Q.DeleteSession(ctx, f.who.Session.ID); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := f.a.deliverLogoutBatch(ctx); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent deliveries %d", calls.Load())
	}
}

func TestBackchannelReceiverCanFetchJWKSWhileProcessingLogout(t *testing.T) {
	var f oauthFixture
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest("GET", "/oauth2/test/jwks", nil).WithContext(ctx)
		req.SetPathValue("slug", "test")
		keys := httptest.NewRecorder()
		f.a.oauthJWKS(keys, req)
		if keys.Code != 200 {
			t.Errorf("RP could not fetch Guard JWKS during logout: %d", keys.Code)
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	f, _ = backchannelFixture(t, server.URL)
	ctx := context.Background()
	if e := f.a.Q.DeleteSession(ctx, f.who.Session.ID); e != nil {
		t.Fatal(e)
	}
	if e := f.a.deliverLogoutBatch(ctx); e != nil {
		t.Fatal(e)
	}
	rows, e := f.a.Q.ListLogoutDeliveries(ctx)
	if e != nil || len(rows) != 1 || rows[0].DeliveredAt == nil {
		t.Fatalf("reentrant recipient could not complete logout: %v %v", rows, e)
	}
}

func TestBackchannelEnqueueFailureAbortsSessionDeletion(t *testing.T) {
	f, tokens := backchannelFixture(t, "https://client.example/logout")
	ctx := context.Background()
	failingInsert(t, f.a, "logout_deliveries")
	if err := f.a.Q.DeleteSession(ctx, f.who.Session.ID); err == nil {
		t.Fatal("session deleted despite failed logout enqueue")
	}
	if _, err := f.a.Q.GetSession(ctx, f.who.Session.ID); err != nil {
		t.Fatalf("session did not survive rollback: %v", err)
	}
	if f.info(tokens["access_token"].(string)) != 200 {
		t.Fatal("grant changed despite rolled back logout")
	}
}
func TestBackchannelTrackingSurvivesTokenCleanup(t *testing.T) {
	f, _ := backchannelFixture(t, "https://client.example/logout")
	ctx := context.Background()
	if _, err := f.a.Pool.Exec(ctx, "UPDATE oauth_tokens SET expires_at=now()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Pool.Exec(ctx, "UPDATE authorization_codes SET expires_at=now()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err := f.a.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Q.DeleteSession(ctx, f.who.Session.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := f.a.Q.ListLogoutDeliveries(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("lost RP participation after token cleanup %v %v", rows, err)
	}
}
func TestBackchannelChangedEndpointCancelsQueuedDelivery(t *testing.T) {
	var requests atomic.Int32
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer old.Close()
	f, _ := backchannelFixture(t, old.URL)
	ctx := context.Background()
	if err := f.a.Q.DeleteSession(ctx, f.who.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Q.SetClientBackchannelLogout(ctx, db.SetClientBackchannelLogoutParams{ID: f.client.ID, BackchannelLogoutUri: "https://new.example/logout"}); err != nil {
		t.Fatal(err)
	}
	if err := f.a.deliverLogoutBatch(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := f.a.Q.ListLogoutDeliveries(ctx)
	if err != nil || len(rows) != 1 || rows[0].CancelledAt == nil || requests.Load() != 0 {
		t.Fatalf("unsafe queued delivery %v %v", rows, err)
	}
}
func TestBackchannelExpiredLeaseRecoversAndRejectsStaleAcknowledgement(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	f, _ := backchannelFixture(t, server.URL)
	ctx := context.Background()
	if err := f.a.Q.DeleteSession(ctx, f.who.Session.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := f.a.Q.ListLogoutDeliveries(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	row := rows[0]
	claimed, err := f.a.Q.ClaimLogoutDelivery(ctx, db.ClaimLogoutDeliveryParams{ID: row.ID, LeaseToken: "worker-died"})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.deliverLogoutBatch(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("ignored active lease")
	}
	if _, err = f.a.Pool.Exec(ctx, "UPDATE logout_deliveries SET lease_until=now()-interval '1 second' WHERE id=$1", row.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.a.deliverLogoutBatch(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.a.Q.RetryLogoutDelivery(ctx, db.RetryLogoutDeliveryParams{ID: claimed.ID, LeaseToken: claimed.LeaseToken, NextAttemptAt: time.Now(), LastError: "stale reply"}); err != nil {
		t.Fatal(err)
	}
	row, err = f.a.Q.GetLogoutDelivery(ctx, row.ID)
	if err != nil || row.DeliveredAt == nil || row.LastError != "" || requests.Load() != 1 {
		t.Fatalf("stale worker overwrote delivery %v %v", row, err)
	}
}
func TestLogoutRetryDelayIsBoundedAndRespectsRetryAfter(t *testing.T) {
	now := time.Now()
	if got := logoutRetryDelay(0, "", now); got != 5*time.Second {
		t.Fatal(got)
	}
	if got := logoutRetryDelay(100, "", now); got != 5*time.Minute {
		t.Fatal(got)
	}
	if got := logoutRetryDelay(0, "120", now); got != 2*time.Minute {
		t.Fatal(got)
	}
	if got := logoutRetryDelay(0, "999999999", now); got != time.Hour {
		t.Fatal(got)
	}
}

func TestBackendSessionDiscoveryAndIntrospectionRoute(t *testing.T) {
	f, tokens := backchannelFixture(t, "")
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/oauth2/test/.well-known/openid-configuration", nil))
	var metadata map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &metadata); e != nil {
		t.Fatal(e)
	}
	if metadata["introspection_endpoint"] != f.a.Config.Domain+"/oauth2/introspect" || metadata["backchannel_logout_supported"] != true || metadata["backchannel_logout_session_supported"] != true {
		t.Fatalf("missing backend session metadata %v", metadata)
	}
	r := httptest.NewRequest("POST", "/oauth2/introspect", strings.NewReader(url.Values{"token": {tokens["access_token"].(string)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(f.client.ClientID, f.client.ClientSecret)
	w = httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	var active map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &active); e != nil {
		t.Fatal(e)
	}
	if w.Code != 200 || active["active"] != true {
		t.Fatalf("real introspection route %d %v", w.Code, active)
	}
	if e := f.a.Q.DeleteSession(context.Background(), f.who.Session.ID); e != nil {
		t.Fatal(e)
	}
	rows, e := f.a.Q.ListLogoutDeliveries(context.Background())
	if e != nil || len(rows) != 0 {
		t.Fatalf("unconfigured client received callback %v %v", rows, e)
	}
}
