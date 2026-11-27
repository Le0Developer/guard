package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
const logoutRetryWindow = 24 * time.Hour

// oauthSID remembers RP participation independently of access tokens so token
// cleanup cannot erase the information needed to notify a logged-in RP later.
// The caller holds the client row lock; the session FK serializes with logout.
func (a *App) oauthSID(ctx context.Context, q *db.Queries, c db.Client, v *identity) (string, error) {
	session, err := q.GetSession(ctx, v.Session.ID)
	if err != nil {
		return "", err
	}
	if session.UserID != v.User.ID || !session.ExpiresAt.After(time.Now()) {
		return "", oauthInvalid
	}
	rp, err := q.UpsertOIDCSession(ctx, db.UpsertOIDCSessionParams{ClientID: c.ID, SessionID: session.ID, UserID: v.User.ID, Sid: security.Token()})
	return rp.Sid, err
}

func (a *App) logoutJWT(ctx context.Context, q *db.Queries, c db.Client, d db.LogoutDelivery) (string, error) {
	key, private, err := a.oauthKey(ctx, q, c)
	if err != nil {
		return "", err
	}
	now := time.Now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "logout+jwt", "kid": fmt.Sprint(key.ID)})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": a.oauthIssuer(c), "aud": c.ClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": d.Jti, "sub": a.oidcSubject(c, d.UserID), "sid": d.Sid, "events": map[string]any{logoutEvent: map[string]any{}}})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Delivery is at-least-once. The stable jti lets an RP recognize retries if its
// previous successful HTTP response was lost. Each retry gets a fresh short JWT
// lifetime so an unavailable RP never has to accept an already-expired token.
func (a *App) deliverLogoutOne(ctx context.Context) (bool, error) {
	var delivery db.LogoutDelivery
	var token string
	worked := false
	// Persist a bounded lease, then release every database lock before HTTP.
	// An RP may need Guard's JWKS or introspection endpoint during its callback.
	err := transaction(ctx, a.Pool, func(q *db.Queries) error {
		d, err := q.PendingLogoutDelivery(ctx)
		if notFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		worked = true
		cancel := func(reason string) error {
			return q.CancelLogoutDelivery(ctx, db.CancelLogoutDeliveryParams{ID: d.ID, LastError: reason, LeaseToken: d.LeaseToken})
		}
		if time.Since(d.CreatedAt) >= logoutRetryWindow {
			return cancel("Delivery retry window expired")
		}
		c, err := q.LockClient(ctx, d.ClientID)
		if err != nil {
			return err
		}
		if c.DeletedAt != nil || c.ClientType != "Oidc" || c.BackchannelLogoutUri != d.Endpoint || d.Endpoint == "" {
			return cancel("Client or logout endpoint changed")
		}
		if err = validateLogoutURI(d.Endpoint); err != nil {
			return cancel("Invalid logout endpoint")
		}
		token, err = a.logoutJWT(ctx, q, c, d)
		if err != nil {
			return err
		}
		delivery, err = q.ClaimLogoutDelivery(ctx, db.ClaimLogoutDeliveryParams{ID: d.ID, LeaseToken: security.Token()})
		return err
	})
	if err != nil || delivery.ID == 0 {
		return worked, err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", delivery.Endpoint, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return worked, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	client := *a.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 10 * time.Second
	response, sendErr := client.Do(request)
	if ctx.Err() != nil {
		if response != nil {
			response.Body.Close()
		}
		return worked, ctx.Err()
	}
	reason := "Transport failure"
	retryAfter := ""
	if sendErr == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode == 200 || response.StatusCode == 204 {
			return worked, a.Q.FinishLogoutDelivery(ctx, db.FinishLogoutDeliveryParams{ID: delivery.ID, LeaseToken: delivery.LeaseToken})
		}
		reason = fmt.Sprintf("HTTP %d", response.StatusCode)
		if response.StatusCode != 408 && response.StatusCode != 429 && response.StatusCode < 500 {
			return worked, a.Q.CancelLogoutDelivery(ctx, db.CancelLogoutDeliveryParams{ID: delivery.ID, LastError: reason, LeaseToken: delivery.LeaseToken})
		}
		retryAfter = response.Header.Get("Retry-After")
	}
	delay := logoutRetryDelay(delivery.Attempts-1, retryAfter, time.Now())
	return worked, a.Q.RetryLogoutDelivery(ctx, db.RetryLogoutDeliveryParams{ID: delivery.ID, NextAttemptAt: time.Now().Add(delay), LastError: reason, LeaseToken: delivery.LeaseToken})
}
func logoutRetryDelay(attempts int32, retryAfter string, now time.Time) time.Duration {
	shift := min(max(attempts, 0), 6)
	delay := min(5*time.Second*time.Duration(1<<shift), 5*time.Minute)
	var requested time.Duration
	if seconds, err := strconv.ParseInt(retryAfter, 10, 32); err == nil && seconds > 0 {
		requested = time.Duration(seconds) * time.Second
	} else if date, err := http.ParseTime(retryAfter); err == nil {
		requested = date.Sub(now)
	}
	if requested > delay {
		delay = min(requested, time.Hour)
	}
	return delay
}
func (a *App) deliverLogoutBatch(ctx context.Context) error {
	for range 25 {
		worked, err := a.deliverLogoutOne(ctx)
		if err != nil {
			return err
		}
		if !worked {
			return nil
		}
	}
	return nil
}
func (a *App) logoutWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.deliverLogoutBatch(ctx); err != nil && ctx.Err() == nil {
				slog.Error("back-channel logout delivery remains pending", "error", err)
			}
		}
	}
}
