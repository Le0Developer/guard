-- name: ListUpstreamProviders :many
SELECT * FROM upstream_providers WHERE deleted_at IS NULL ORDER BY name,id;
-- name: EnabledUpstreamProviders :many
SELECT * FROM upstream_providers WHERE enabled AND deleted_at IS NULL ORDER BY name,id;
-- name: GetUpstreamProvider :one
SELECT * FROM upstream_providers WHERE id=$1;
-- name: LockUpstreamProvider :one
SELECT * FROM upstream_providers WHERE id=$1 FOR UPDATE;
-- name: UpstreamProviderBySlug :one
SELECT * FROM upstream_providers WHERE slug=$1;
-- name: CreateUpstreamProvider :one
INSERT INTO upstream_providers (slug,name,issuer,authorize_url,token_url,userinfo_url,jwks_url,client_id,client_secret,scopes,pkce,signing_alg,enabled,backchannel_logout_enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *;
-- name: TryCreateUpstreamProvider :one
INSERT INTO upstream_providers (slug,name,issuer,authorize_url,token_url,userinfo_url,jwks_url,client_id,client_secret,scopes,pkce,signing_alg,enabled,backchannel_logout_enabled)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (slug) DO NOTHING RETURNING *;
-- name: UpdateUpstreamProvider :one
UPDATE upstream_providers SET name=$2,issuer=$3,authorize_url=$4,token_url=$5,userinfo_url=$6,jwks_url=$7,client_id=$8,client_secret=$9,scopes=$10,pkce=$11,signing_alg=$12,enabled=$13,backchannel_logout_enabled=$14,revision=revision+1,updated_at=now() WHERE id=$1 RETURNING *;
-- name: DeleteUpstreamProvider :exec
UPDATE upstream_providers SET enabled=false,deleted_at=now(),revision=revision+1,updated_at=now() WHERE id=$1;
-- name: DeleteSessionsForProvider :exec
DELETE FROM sessions WHERE id IN (SELECT session_id FROM upstream_sessions WHERE provider_id=$1);
-- name: DeleteProviderLoginSessions :exec
DELETE FROM login_sessions WHERE provider=(SELECT slug FROM upstream_providers WHERE upstream_providers.id=$1);
-- name: BindUpstreamPendingLogin :exec
INSERT INTO upstream_pending_logins (login_session_id,provider_id,user_id,matched_email,subject,sid,provider_revision,token_issued_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);
-- name: GetUpstreamPendingLogin :one
SELECT * FROM upstream_pending_logins WHERE login_session_id=$1;
-- name: BindUpstreamSession :exec
INSERT INTO upstream_sessions (session_id,provider_id,subject,sid,provider_revision,token_issued_at) VALUES ($1,$2,$3,$4,$5,$6);
-- name: GetUpstreamSession :one
SELECT * FROM upstream_sessions WHERE session_id=$1;
-- name: RecordUpstreamLogout :one
INSERT INTO upstream_logout_events (provider_id,provider_revision,jti,subject,sid,issued_at,expires_at,retain_until)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING *;
-- name: HasUpstreamLogout :one
SELECT EXISTS(SELECT 1 FROM upstream_logout_events WHERE provider_id=$1 AND provider_revision=$2 AND issued_at >= sqlc.arg(token_issued_at) AND retain_until>now()
AND ((sid='' AND subject=sqlc.arg(subject)) OR (sid<>'' AND sid=sqlc.arg(sid) AND (subject='' OR subject=sqlc.arg(subject)))));
-- name: DeleteUpstreamLogoutSessions :exec
DELETE FROM sessions WHERE id IN (SELECT session_id FROM upstream_sessions WHERE provider_id=$1 AND provider_revision=$2 AND token_issued_at <= sqlc.arg(issued_at)
AND (sqlc.arg(sid)::text='' OR sid=sqlc.arg(sid)) AND (sqlc.arg(subject)::text='' OR subject=sqlc.arg(subject)));
-- name: DeleteUpstreamLogoutPending :exec
DELETE FROM login_sessions WHERE id IN (SELECT login_session_id FROM upstream_pending_logins WHERE provider_id=$1 AND provider_revision=$2 AND token_issued_at <= sqlc.arg(issued_at)
AND (sqlc.arg(sid)::text='' OR sid=sqlc.arg(sid)) AND (sqlc.arg(subject)::text='' OR subject=sqlc.arg(subject)));
-- name: DeleteExpiredUpstreamLogoutEvents :exec
DELETE FROM upstream_logout_events WHERE retain_until < now();
-- name: UpstreamLogoutSessionSubjects :many
SELECT s.id,s.user_id FROM sessions s JOIN upstream_sessions u ON u.session_id=s.id WHERE u.provider_id=$1 AND u.provider_revision=$2 AND u.token_issued_at <= sqlc.arg(issued_at)
AND (sqlc.arg(sid)::text='' OR u.sid=sqlc.arg(sid)) AND (sqlc.arg(subject)::text='' OR u.subject=sqlc.arg(subject)) ORDER BY s.id;

-- name: SetUpstreamProviderSetup :one
UPDATE upstream_providers SET configuration_mode=$2,discovery_url=$3,subject_field=$4,email_field=$5,email_verified_field=$6,client_auth_method=$7 WHERE id=$1 RETURNING *;
