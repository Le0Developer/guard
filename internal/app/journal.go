package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/le0developer/guard/internal/db"
	"github.com/le0developer/guard/internal/ids"
	"github.com/le0developer/guard/internal/security"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

func eventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func (a *App) persistAccess(ctx context.Context, q *db.Queries, c db.Client, user *ids.UserID, session *ids.SessionID, source, dedupe string, data any) (db.AccessLog, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return db.AccessLog{}, err
	}
	v, err := q.CreateAccessLog(ctx, db.CreateAccessLogParams{EventID: eventID(), DedupeKey: dedupe, ClientID: c.ID, UserID: user, SessionID: session, Source: source, Data: b})
	if err != nil {
		return v, err
	}
	if a.Config.ExportURL != "" {
		_, err = q.CreateAccessLogDelivery(ctx, db.CreateAccessLogDeliveryParams{LogID: v.ID, NextAttemptAt: time.Now()})
	}
	return v, err
}
func (a *App) recordAccess(ctx context.Context, c db.Client, user *ids.UserID, session *ids.SessionID, source string, data map[string]any) error {
	if !c.DetailedLogging {
		return nil
	}
	data["protocol"] = source
	data["request_id"] = eventID()
	err := transaction(ctx, a.Pool, func(q *db.Queries) error {
		_, err := a.persistAccess(ctx, q, c, user, session, "request", "request:"+security.Token(), data)
		return err
	})
	if err != nil {
		slog.Error("access journal write failed", "client_id", c.ID, "error", err)
	}
	return err
}

type reportInput struct {
	SessionToken string         `json:"session_token"`
	ReportID     string         `json:"report_id"`
	Event        string         `json:"event"`
	Outcome      string         `json:"outcome"`
	Resource     string         `json:"resource,omitempty"`
	OccurredAt   *time.Time     `json:"occurred_at,omitempty"`
	Metadata     map[string]any `json:"metadata"`
}

func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func safeResource(s string) (string, error) {
	if len(s) > 2048 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", errors.New("invalid resource")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.IsAbs() && (u.Scheme == "https" || u.Scheme == "http") {
		if u.User != nil {
			return "", errors.New("resource URLs cannot contain credentials")
		}
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		return u.String(), nil
	}
	clean, _, _ := strings.Cut(s, "?")
	clean, _, _ = strings.Cut(clean, "#")
	return clean, nil
}
func validateReport(v *reportInput) error {
	if !validUUID(v.ReportID) {
		return errors.New("report_id must be a non-nil UUID")
	}
	v.ReportID = strings.ToLower(v.ReportID)
	if len(v.Event) < 1 || len(v.Event) > 100 || strings.IndexFunc(v.Event, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r))
	}) >= 0 {
		return errors.New("invalid event name")
	}
	switch v.Outcome {
	case "success", "failure", "denied", "started", "completed":
	default:
		return errors.New("invalid outcome")
	}
	if v.Resource != "" {
		s, err := safeResource(v.Resource)
		if err != nil {
			return err
		}
		v.Resource = s
	}
	if len(v.Metadata) > 24 {
		return errors.New("metadata supports at most 24 fields")
	}
	for key, value := range v.Metadata {
		normalized := strings.ToLower(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, key))
		if key == "" || len(key) > 64 || strings.IndexFunc(key, unicode.IsControl) >= 0 {
			return errors.New("invalid metadata field")
		}
		for _, secret := range []string{"password", "passwd", "secret", "token", "cookie", "authorization", "credential", "apikey"} {
			if strings.Contains(normalized, secret) {
				return errors.New("secret metadata fields are not allowed")
			}
		}
		switch normalized {
		case "code", "userid", "sessionid", "clientid", "actorid", "subjectid":
			return errors.New("identity metadata fields are not allowed")
		}
		switch x := value.(type) {
		case string:
			if len(x) > 256 || strings.IndexFunc(x, unicode.IsControl) >= 0 {
				return errors.New("invalid metadata string")
			}
			if strings.HasPrefix(x, "https://") || strings.HasPrefix(x, "http://") {
				s, err := safeResource(x)
				if err != nil {
					return err
				}
				v.Metadata[key] = s
			}
		case nil, bool, float64, json.Number:
		default:
			return errors.New("metadata values must be scalar")
		}
	}
	return nil
}

type reportFailure struct {
	status int
	code   string
}

func (e reportFailure) Error() string { return e.code }
func (a *App) eventReport(w http.ResponseWriter, r *http.Request) {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		oauthError(w, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var input reportInput
	if err := decoder.Decode(&input); err != nil {
		status := 400
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			status = 413
		}
		jsonResponse(w, status, map[string]string{"error": "invalid_request"})
		return
	}
	if decoder.Decode(new(any)) != io.EOF || validateReport(&input) != nil {
		oauthError(w, "invalid_request")
		return
	}
	var result db.AccessLog
	created := false
	err := transaction(r.Context(), a.Pool, func(q *db.Queries) error {
		if len(r.Header.Values("Authorization")) != 1 {
			return reportFailure{401, "invalid_client"}
		}
		id, secret, ok := r.BasicAuth()
		if !ok {
			return reportFailure{401, "invalid_client"}
		}
		id, e1 := url.QueryUnescape(id)
		secret, e2 := url.QueryUnescape(secret)
		if e1 != nil || e2 != nil {
			return reportFailure{401, "invalid_client"}
		}
		c, err := q.LockClientByClientId(r.Context(), id)
		if err != nil {
			if notFound(err) {
				return reportFailure{401, "invalid_client"}
			}
			return err
		}
		if c.ClientType == "Saml" || c.Disabled || c.DeletedAt != nil || secret == "" || !security.Equal(secret, c.ClientSecret) {
			return reportFailure{401, "invalid_client"}
		}
		if !c.AllowEventReports {
			return reportFailure{403, "access_denied"}
		}
		if len(input.SessionToken) < 1 || len(input.SessionToken) > 512 {
			return reportFailure{401, "invalid_token"}
		}
		var user ids.UserID
		var session ids.SessionID
		var grant *ids.AuthorizationCodeID
		var forward *ids.ForwardAuthSessionID
		var start time.Time
		switch c.ClientType {
		case "Oidc":
			t, err := q.OAuthTokenByAccessTokenHash(r.Context(), security.Hash(input.SessionToken))
			if err != nil {
				if notFound(err) {
					return reportFailure{401, "invalid_token"}
				}
				return err
			}
			if t.ClientID != c.ID || t.RevokedAt != nil || !t.AccessExpiresAt.After(time.Now()) || !t.ExpiresAt.After(time.Now()) {
				return reportFailure{401, "invalid_token"}
			}
			user, session, grant, start = t.UserID, t.SessionID, &t.CodeID, t.CreatedAt
		case "ForwardAuth":
			t, err := q.ForwardAuthSessionByTokenHash(r.Context(), security.Hash(input.SessionToken))
			if err != nil {
				if notFound(err) {
					return reportFailure{401, "invalid_token"}
				}
				return err
			}
			allowed, err := a.forwardAllowed(r.Context(), q, c, t.Origin)
			if err != nil {
				return err
			}
			if t.ClientID != c.ID || !t.ExpiresAt.After(time.Now()) || !allowed {
				return reportFailure{401, "invalid_token"}
			}
			user, session, forward, start = t.UserID, t.SessionID, &t.ID, t.CreatedAt
		default:
			return reportFailure{403, "access_denied"}
		}
		v, err := a.sessionByID(r.Context(), q, session)
		if err != nil {
			return err
		}
		if v == nil || v.User.ID != user {
			return reportFailure{401, "invalid_token"}
		}
		allowed, err := a.permitted(r.Context(), q, c.ID, user)
		if err != nil {
			return err
		}
		if !allowed {
			return reportFailure{403, "access_denied"}
		}
		if input.OccurredAt != nil && (input.OccurredAt.Before(start) || input.OccurredAt.After(time.Now().Add(5*time.Minute))) {
			return reportFailure{400, "invalid_request"}
		}
		sessionToken := input.SessionToken
		input.SessionToken = ""
		public, _ := json.Marshal(input)
		if strings.Contains(string(public), sessionToken) || strings.Contains(string(public), c.ClientSecret) {
			return reportFailure{400, "invalid_request"}
		}
		fingerprint := security.Hash(string(public))
		dedupe := fmt.Sprintf("report:%d:%s", c.ID, input.ReportID)
		old, err := q.AccessLogByDedupeKey(r.Context(), dedupe)
		if err == nil {
			var data struct {
				Fingerprint string                    `json:"fingerprint"`
				Grant       *ids.AuthorizationCodeID  `json:"grant_id"`
				Forward     *ids.ForwardAuthSessionID `json:"forward_session_id"`
			}
			if json.Unmarshal(old.Data, &data) != nil || data.Fingerprint != fingerprint || old.UserID == nil || *old.UserID != user || old.SessionID == nil || *old.SessionID != session || !samePtr(grant, data.Grant) || !samePtr(forward, data.Forward) {
				return reportFailure{409, "report_conflict"}
			}
			result = old
			return nil
		}
		if !notFound(err) {
			return err
		}
		window := time.Now().Unix() / 60
		rate, err := q.GetEventReportRate(r.Context(), c.ID)
		if notFound(err) {
			_, err = q.CreateEventReportRate(r.Context(), db.CreateEventReportRateParams{ClientID: c.ID, WindowStart: window, Count: 1})
		} else if err == nil {
			count := int32(1)
			if rate.WindowStart == window {
				count = rate.Count + 1
			}
			limit := a.Config.ReportLimit
			if limit < 1 {
				limit = 600
			}
			if count > limit {
				return reportFailure{429, "rate_limited"}
			}
			_, err = q.UpdateEventReportRate(r.Context(), db.UpdateEventReportRateParams{ClientID: c.ID, WindowStart: window, Count: count})
		}
		if err != nil {
			return err
		}
		result, err = a.persistAccess(r.Context(), q, c, &user, &session, "application", dedupe, map[string]any{"fingerprint": fingerprint, "grant_id": grant, "forward_session_id": forward, "report": input, "decision": input.Outcome, "protocol": "application", "path": input.Resource, "status": 202})
		if err != nil {
			return err
		}
		created = true
		return a.audit(r.Context(), q, user, "ApplicationEvent", map[string]any{"client_id": c.ID, "session_id": session, "event_id": result.EventID, "event": input.Event, "outcome": input.Outcome})
	})
	if err != nil {
		var failure reportFailure
		if errors.As(err, &failure) {
			if failure.status == 429 {
				w.Header().Set("Retry-After", fmt.Sprint(60-time.Now().Unix()%60))
			}
			if failure.status == 401 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Guard"`)
			}
			jsonResponse(w, failure.status, map[string]string{"error": failure.code})
		} else {
			a.serverError(w, r, err)
		}
		return
	}
	status := 200
	if created {
		status = 202
	}
	jsonResponse(w, status, map[string]any{"event_id": result.EventID, "report_id": input.ReportID, "received_at": result.CreatedAt})
}
func samePtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func (a *App) Background(ctx context.Context) {
	go a.logoutWorker(ctx)
	for range 4 {
		go a.scimWorker(ctx)
	}
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	export := time.NewTicker(time.Second)
	defer export.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanup.C:
			if err := a.cleanup(ctx); err != nil {
				slog.Error("authentication cleanup", "error", err)
			}
		case <-export.C:
			if a.Config.ExportURL != "" {
				if err := a.exportBatch(ctx); err != nil {
					slog.Error("access journal delivery remains pending", "error", err)
				}
			}
		}
	}
}
func (a *App) cleanup(ctx context.Context) error {
	return transaction(ctx, a.Pool, func(q *db.Queries) error {
		for _, fn := range []func(context.Context) error{q.CleanSAML, q.EraseSAMLRetiredSecrets, q.DeleteExpiredUpstreamLogoutEvents, q.DeleteExpiredCeremonies, q.DeleteExpiredForwardRequests, q.DeleteExpiredForwardSessions, q.DeleteExpiredOAuthTokens, q.DeleteExpiredCodes, q.DeleteExpiredKeys, q.DeleteExpiredLogins, q.DeleteExpiredSessions} {
			if err := fn(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}
func (a *App) exportBatch(ctx context.Context) error {
	deliveries, err := a.Q.PendingDeliveries(ctx)
	if err != nil || len(deliveries) == 0 {
		return err
	}
	events := []any{}
	for _, d := range deliveries {
		log, err := a.Q.GetAccessLog(ctx, d.LogID)
		if err != nil {
			return err
		}
		events = append(events, map[string]any{"event_id": log.EventID, "sequence": log.ID, "received_at": log.CreatedAt, "client_id": log.ClientID, "user_id": log.UserID, "session_id": log.SessionID, "source": log.Source, "data": json.RawMessage(log.Data)})
	}
	body, err := json.Marshal(map[string]any{"version": 1, "instance": a.Config.Domain, "events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.Config.ExportURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Config.ExportToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.Config.ExportToken)
	}
	resp, sendErr := a.HTTP.Do(req)
	outcome := ""
	if sendErr != nil {
		outcome = "Transport failure"
	} else {
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			outcome = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
	}
	return transaction(ctx, a.Pool, func(q *db.Queries) error {
		for _, d := range deliveries {
			attempts := d.Attempts + 1
			delay := attempts
			if delay > 8 {
				delay = 8
			}
			next := time.Now().Add(time.Duration(1<<delay) * time.Second)
			var delivered *time.Time
			if outcome == "" {
				delivered = ptr(time.Now())
			}
			_, err := q.UpdateAccessLogDelivery(ctx, db.UpdateAccessLogDeliveryParams{LogID: d.LogID, Attempts: attempts, NextAttemptAt: next, DeliveredAt: delivered, LastError: outcome})
			if err != nil {
				return err
			}
		}
		return nil
	})
}
