-- name: OAuthConsumeCode :exec
UPDATE authorization_codes SET consumed_at = now() WHERE id = $1;
-- name: OAuthRevokeFamily :exec
UPDATE oauth_tokens SET revoked_at = now() WHERE family = $1;
-- name: OAuthRevokeCode :exec
UPDATE oauth_tokens SET revoked_at = now() WHERE code_id = $1;
-- name: OAuthRevokeToken :exec
UPDATE oauth_tokens SET revoked_at = now() WHERE id = $1;
