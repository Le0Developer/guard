-- name: SetClientBackchannelLogout :one
UPDATE clients SET backchannel_logout_uri = $2, backchannel_logout_session_required = $3, updated_at=now() WHERE id=$1 RETURNING *;

-- name: UpsertOIDCSession :one
INSERT INTO oidc_sessions (client_id, session_id, user_id, sid) VALUES ($1,$2,$3,$4)
ON CONFLICT(client_id,session_id) DO UPDATE SET client_id=EXCLUDED.client_id
RETURNING *;

-- name: OIDCSessionForClient :one
SELECT * FROM oidc_sessions WHERE client_id=$1 AND session_id=$2;

-- name: OIDCSessionsForSession :many
SELECT * FROM oidc_sessions WHERE session_id=$1 ORDER BY id;

-- name: PendingLogoutDelivery :one
SELECT * FROM logout_deliveries WHERE delivered_at IS NULL AND cancelled_at IS NULL AND next_attempt_at<=now() AND (lease_until IS NULL OR lease_until<=now())
ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: GetLogoutDelivery :one
SELECT * FROM logout_deliveries WHERE id=$1;

-- name: ListLogoutDeliveries :many
SELECT * FROM logout_deliveries ORDER BY id;

-- name: ClaimLogoutDelivery :one
UPDATE logout_deliveries SET attempts=attempts+1, lease_token=$2, lease_until=now()+interval '30 seconds' WHERE id=$1 RETURNING *;

-- name: FinishLogoutDelivery :exec
UPDATE logout_deliveries SET delivered_at=now(), last_error='', lease_token='', lease_until=NULL WHERE id=$1 AND lease_token=$2;

-- name: RetryLogoutDelivery :exec
UPDATE logout_deliveries SET next_attempt_at=$2, last_error=$3, lease_token='', lease_until=NULL WHERE id=$1 AND lease_token=$4;

-- name: CancelLogoutDelivery :exec
UPDATE logout_deliveries SET cancelled_at=now(), last_error=$2, lease_token='', lease_until=NULL WHERE id=$1 AND lease_token=$3;
