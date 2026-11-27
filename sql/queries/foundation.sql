-- name: ClientAccessRulesByClientId :many
SELECT * FROM client_access_rules WHERE client_id = $1 ORDER BY priority, access_control DESC;

-- name: GroupMembersByUserId :many
SELECT * FROM group_members WHERE user_id = $1;

-- name: GroupMembersByGroupId :many
SELECT * FROM group_members WHERE group_id = $1;

-- name: UsersByEmail :many
SELECT * FROM users WHERE lower(email) = lower($1) AND NOT disabled AND deleted_at IS NULL LIMIT 2;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: BootstrapUser :one
INSERT INTO users (id, username, password, role, webauthn_user_id) VALUES (0, 'system', $1, 'Admin', $2) ON CONFLICT (id) DO NOTHING RETURNING *;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at < now();
-- name: DeleteExpiredLogins :exec
DELETE FROM login_sessions WHERE expires_at < now();
-- name: DeleteExpiredCeremonies :exec
DELETE FROM mfa_ceremonies WHERE expires_at < now();
-- name: DeleteExpiredForwardRequests :exec
DELETE FROM forward_auth_requests WHERE expires_at < now();
-- name: DeleteExpiredForwardSessions :exec
DELETE FROM forward_auth_sessions WHERE expires_at < now();
-- name: DeleteExpiredOAuthTokens :exec
DELETE FROM oauth_tokens WHERE expires_at < now();
-- name: DeleteExpiredCodes :exec
DELETE FROM authorization_codes WHERE expires_at < now() AND NOT EXISTS (SELECT 1 FROM oauth_tokens WHERE code_id = authorization_codes.id);
-- name: DeleteExpiredKeys :exec
DELETE FROM signing_keys WHERE expires_at < now();

-- name: PendingDeliveries :many
SELECT * FROM access_log_deliveries WHERE delivered_at IS NULL AND next_attempt_at <= now() ORDER BY log_id LIMIT 100;

-- name: SetSessionAuthTime :exec
UPDATE sessions SET auth_time = $2 WHERE id = $1;
