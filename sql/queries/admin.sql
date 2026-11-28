-- name: AdminInvalidateUserLogins :exec
UPDATE users SET mfa_revision = mfa_revision + 1, updated_at = now() WHERE id = $1;

-- name: AdminDeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: AdminDeleteUserCeremonies :exec
DELETE FROM mfa_ceremonies WHERE user_id = $1;

-- name: AdminDeleteUserMemberships :exec
DELETE FROM group_members WHERE user_id = $1;

-- name: AdminDeleteGroupMemberships :exec
DELETE FROM group_members WHERE group_id = $1;

-- name: AdminDeleteGroupRules :exec
DELETE FROM client_access_rules WHERE group_id = $1;

-- name: AdminDeleteClientRules :exec
DELETE FROM client_access_rules WHERE client_id = $1;

-- name: AdminDeleteClientRedirects :exec
DELETE FROM client_redirects WHERE client_id = $1;

-- name: AdminDeleteClientCodes :exec
DELETE FROM authorization_codes WHERE client_id = $1;

-- name: AdminDeleteClientRequests :exec
DELETE FROM forward_auth_requests WHERE client_id = $1;

-- name: AdminDeleteClientSessions :exec
DELETE FROM forward_auth_sessions WHERE client_id = $1;

-- name: AdminAddMember :exec
INSERT INTO group_members (group_id,user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING;

-- name: AdminSaveRule :exec
INSERT INTO client_access_rules (client_id,group_id,priority,access_control) VALUES ($1,$2,$3,$4)
ON CONFLICT (client_id,group_id) DO UPDATE SET priority = EXCLUDED.priority, access_control = EXCLUDED.access_control;

-- name: AdminAuditPage :many
SELECT * FROM audit_logs WHERE id < sqlc.arg(before_id) ORDER BY id DESC LIMIT 101;

-- name: AdminAccessPage :many
SELECT * FROM access_logs
WHERE id < sqlc.arg(before_id)
AND (NOT sqlc.arg(has_client)::boolean OR client_id = sqlc.arg(client_id))
AND (NOT sqlc.arg(has_session)::boolean OR session_id = sqlc.arg(session_id))
AND (sqlc.arg(source_filter)::text = '' OR source = sqlc.arg(source_filter)::text)
ORDER BY id DESC LIMIT 101;

-- name: AdminDeliveryCounts :one
SELECT count(*) FILTER (WHERE delivered_at IS NULL)::bigint AS pending,
count(*) FILTER (WHERE delivered_at IS NULL AND last_error <> '')::bigint AS failed
FROM access_log_deliveries;

-- name: LockClientsForGroupDeletion :exec
-- Serialize client creation and row locks before locking the group.
LOCK TABLE clients IN EXCLUSIVE MODE;

-- name: SetClientDisabled :one
UPDATE clients SET disabled = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: AdminProviderSessions :many
SELECT session_id FROM upstream_sessions WHERE provider_id = $1 ORDER BY session_id;

-- name: AdminGroupAccessRules :many
SELECT r.client_id, c.name AS client_name, r.priority, r.access_control
FROM client_access_rules r JOIN clients c ON c.id = r.client_id
WHERE r.group_id = $1 ORDER BY r.client_id;
