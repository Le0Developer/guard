package app

import (
	"context"
	"encoding/json"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/security"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestApplicationReportIdempotencyConflictAndRateLimit(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	a.Config.ReportLimit = 1
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "reporter", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Q.CreateSession(ctx, db.CreateSessionParams{UserID: u.ID, TokenHash: security.Hash("session"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Reports", Slug: "reports", ClientType: "ForwardAuth", ClientID: "reports", ClientSecret: "super-secret-client", AllowEventReports: true, SessionLifetimeS: 600})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.CreateClientRedirect(ctx, db.CreateClientRedirectParams{ClientID: c.ID, RedirectUri: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Q.CreateForwardAuthSession(ctx, db.CreateForwardAuthSessionParams{TokenHash: security.Hash("app-session-token"), ClientID: c.ID, UserID: u.ID, SessionID: s.ID, Origin: "https://app.example.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	input := `{"session_token":"app-session-token","report_id":"11111111-1111-4111-8111-111111111111","event":"file.saved","outcome":"success","resource":"https://app.example.com/file?token=redact","metadata":{"count":1}}`
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/oauth2/event", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(c.ClientID, c.ClientSecret)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		return w
	}
	first := post(input)
	if first.Code != 202 {
		t.Fatalf("first %d %s", first.Code, first.Body.String())
	}
	second := post(input)
	if second.Code != 200 {
		t.Fatalf("duplicate %d %s", second.Code, second.Body.String())
	}
	var x, y map[string]any
	json.Unmarshal(first.Body.Bytes(), &x)
	json.Unmarshal(second.Body.Bytes(), &y)
	if x["event_id"] != y["event_id"] {
		t.Fatal("duplicate created a new event")
	}
	conflict := post(strings.Replace(input, "file.saved", "file.deleted", 1))
	if conflict.Code != 409 {
		t.Fatalf("conflict %d %s", conflict.Code, conflict.Body.String())
	}
	limited := post(strings.Replace(input, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1))
	if limited.Code != 429 {
		t.Fatalf("limit %d %s", limited.Code, limited.Body.String())
	}
	logs, err := a.Q.ListAccessLogs(ctx)
	if err != nil || len(logs) != 1 || strings.Contains(string(logs[0].Data), "redact") || strings.Contains(string(logs[0].Data), "app-session-token") {
		t.Fatalf("unsafe logs %+v %v", logs, err)
	}
	if err = a.Q.DeleteSession(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	revoked := post(input)
	if revoked.Code != 401 {
		t.Fatalf("revoked session %d %s", revoked.Code, revoked.Body.String())
	}
}
func TestCollectorRetriesWithoutLosingEvents(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	u, err := a.Q.CreateUser(ctx, db.CreateUserParams{Username: "collector", Role: "User", WebauthnUserID: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.Q.CreateClient(ctx, db.CreateClientParams{Name: "Collector", Slug: "collector", ClientType: "Oidc", ClientID: "collector", ClientSecret: "secret", SessionLifetimeS: 600, DetailedLogging: true})
	if err != nil {
		t.Fatal(err)
	}
	status := 503
	calls := 0
	var firstEvent string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer append-only" {
			t.Error("missing collector authentication")
		}
		var body struct {
			Events []struct {
				EventID string `json:"event_id"`
			} `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Events) != 1 {
			t.Errorf("invalid collector envelope %v", err)
		} else {
			if firstEvent == "" {
				firstEvent = body.Events[0].EventID
			} else if firstEvent != body.Events[0].EventID {
				t.Error("retry changed event identity")
			}
		}
		w.WriteHeader(status)
	}))
	defer collector.Close()
	a.Config.ExportURL = collector.URL
	a.Config.ExportToken = "append-only"
	a.recordAccess(ctx, c, &u.ID, nil, "oauth2", map[string]any{"decision": "allowed", "path": "/oauth2/token", "status": 200})
	if err = a.exportBatch(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := a.Q.ListAccessLogDeliverys(ctx)
	if err != nil || len(rows) != 1 || rows[0].DeliveredAt != nil || rows[0].Attempts != 1 {
		t.Fatalf("lost retry %+v %v", rows, err)
	}
	d := rows[0]
	_, err = a.Q.UpdateAccessLogDelivery(ctx, db.UpdateAccessLogDeliveryParams{LogID: d.LogID, Attempts: d.Attempts, NextAttemptAt: time.Now().Add(-time.Second), LastError: d.LastError})
	if err != nil {
		t.Fatal(err)
	}
	status = 204
	if err = a.exportBatch(ctx); err != nil {
		t.Fatal(err)
	}
	d, err = a.Q.GetAccessLogDelivery(ctx, d.LogID)
	if err != nil || d.DeliveredAt == nil || d.Attempts != 2 || calls != 2 {
		t.Fatalf("delivery %+v calls %d %v", d, calls, err)
	}
}
