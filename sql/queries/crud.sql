-- name: GetUser :one
SELECT * FROM users WHERE id = sqlc.arg(id);

-- name: LockUser :one
SELECT * FROM users WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListUsers :many
SELECT * FROM users ORDER BY id;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = sqlc.arg(id);

-- name: CreateUser :one
INSERT INTO users (username, email, force_password_reset, password, role, disabled, mfa_revision, mfa_failures, mfa_window, webauthn_user_id, deleted_at) VALUES (sqlc.arg(username), sqlc.arg(email), sqlc.arg(force_password_reset), sqlc.arg(password), sqlc.arg(role), sqlc.arg(disabled), sqlc.arg(mfa_revision), sqlc.arg(mfa_failures), sqlc.narg(mfa_window), sqlc.arg(webauthn_user_id), sqlc.narg(deleted_at)) RETURNING *;

-- name: UpdateUser :one
UPDATE users SET force_password_reset = sqlc.arg(force_password_reset), username = sqlc.arg(username), email = sqlc.arg(email), password = sqlc.arg(password), role = sqlc.arg(role), disabled = sqlc.arg(disabled), mfa_revision = sqlc.arg(mfa_revision), mfa_failures = sqlc.arg(mfa_failures), mfa_window = sqlc.narg(mfa_window), webauthn_user_id = sqlc.arg(webauthn_user_id), deleted_at = sqlc.narg(deleted_at), updated_at = now() WHERE id = sqlc.arg(id) RETURNING *;

-- name: UserByUsername :one
SELECT * FROM users WHERE username = sqlc.arg(username);

-- name: LockUserByUsername :one
SELECT * FROM users WHERE username = sqlc.arg(username) FOR UPDATE;

-- name: GetSession :one
SELECT * FROM sessions WHERE id = sqlc.arg(id);

-- name: LockSession :one
SELECT * FROM sessions WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListSessions :many
SELECT * FROM sessions ORDER BY id;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = sqlc.arg(id);

-- name: CreateSession :one
INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (sqlc.arg(user_id), sqlc.arg(token_hash), sqlc.arg(expires_at)) RETURNING *;

-- name: UpdateSession :one
UPDATE sessions SET user_id = sqlc.arg(user_id), token_hash = sqlc.arg(token_hash), expires_at = sqlc.arg(expires_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: SessionsByUserId :many
SELECT * FROM sessions WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: SessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = sqlc.arg(token_hash);

-- name: LockSessionByTokenHash :one
SELECT * FROM sessions WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: GetLoginSession :one
SELECT * FROM login_sessions WHERE id = sqlc.arg(id);

-- name: LockLoginSession :one
SELECT * FROM login_sessions WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListLoginSessions :many
SELECT * FROM login_sessions ORDER BY id;

-- name: DeleteLoginSession :exec
DELETE FROM login_sessions WHERE id = sqlc.arg(id);

-- name: CreateLoginSession :one
INSERT INTO login_sessions (token_hash, internal_token, redirect_uri, provider, state, expires_at) VALUES (sqlc.arg(token_hash), sqlc.arg(internal_token), sqlc.arg(redirect_uri), sqlc.arg(provider), sqlc.arg(state), sqlc.arg(expires_at)) RETURNING *;

-- name: UpdateLoginSession :one
UPDATE login_sessions SET token_hash = sqlc.arg(token_hash), internal_token = sqlc.arg(internal_token), redirect_uri = sqlc.arg(redirect_uri), provider = sqlc.arg(provider), state = sqlc.arg(state), expires_at = sqlc.arg(expires_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: LoginSessionByTokenHash :one
SELECT * FROM login_sessions WHERE token_hash = sqlc.arg(token_hash);

-- name: LockLoginSessionByTokenHash :one
SELECT * FROM login_sessions WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = sqlc.arg(id);

-- name: LockGroup :one
SELECT * FROM groups WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListGroups :many
SELECT * FROM groups ORDER BY id;

-- name: DeleteGroup :exec
DELETE FROM groups WHERE id = sqlc.arg(id);

-- name: CreateGroup :one
INSERT INTO groups (name, deleted_at) VALUES (sqlc.arg(name), sqlc.narg(deleted_at)) RETURNING *;

-- name: UpdateGroup :one
UPDATE groups SET name = sqlc.arg(name), deleted_at = sqlc.narg(deleted_at), updated_at = now() WHERE id = sqlc.arg(id) RETURNING *;

-- name: GetGroupMember :one
SELECT * FROM group_members WHERE group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id);

-- name: LockGroupMember :one
SELECT * FROM group_members WHERE group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id) FOR UPDATE;

-- name: ListGroupMembers :many
SELECT * FROM group_members ORDER BY group_id,user_id;

-- name: DeleteGroupMember :exec
DELETE FROM group_members WHERE group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id);

-- name: CreateGroupMember :one
INSERT INTO group_members (group_id, user_id) VALUES (sqlc.arg(group_id), sqlc.arg(user_id)) RETURNING *;

-- name: GetClient :one
SELECT * FROM clients WHERE id = sqlc.arg(id);

-- name: LockClient :one
SELECT * FROM clients WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListClients :many
SELECT * FROM clients ORDER BY id;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = sqlc.arg(id);

-- name: CreateClient :one
INSERT INTO clients (name, slug, client_type, client_id, client_secret, session_lifetime_s, require_pkce, detailed_logging, allow_event_reports, deleted_at) VALUES (sqlc.arg(name), sqlc.arg(slug), sqlc.arg(client_type), sqlc.arg(client_id), sqlc.arg(client_secret), sqlc.arg(session_lifetime_s), sqlc.arg(require_pkce), sqlc.arg(detailed_logging), sqlc.arg(allow_event_reports), sqlc.narg(deleted_at)) RETURNING *;

-- name: UpdateClient :one
UPDATE clients SET name = sqlc.arg(name), slug = sqlc.arg(slug), client_type = sqlc.arg(client_type), client_id = sqlc.arg(client_id), client_secret = sqlc.arg(client_secret), session_lifetime_s = sqlc.arg(session_lifetime_s), require_pkce = sqlc.arg(require_pkce), detailed_logging = sqlc.arg(detailed_logging), allow_event_reports = sqlc.arg(allow_event_reports), deleted_at = sqlc.narg(deleted_at), updated_at = now() WHERE id = sqlc.arg(id) RETURNING *;

-- name: ClientBySlug :one
SELECT * FROM clients WHERE slug = sqlc.arg(slug);

-- name: LockClientBySlug :one
SELECT * FROM clients WHERE slug = sqlc.arg(slug) FOR UPDATE;

-- name: ClientsByClientId :many
SELECT * FROM clients WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: ClientByClientId :one
SELECT * FROM clients WHERE client_id = sqlc.arg(client_id);

-- name: LockClientByClientId :one
SELECT * FROM clients WHERE client_id = sqlc.arg(client_id) FOR UPDATE;

-- name: GetClientRedirect :one
SELECT * FROM client_redirects WHERE id = sqlc.arg(id);

-- name: LockClientRedirect :one
SELECT * FROM client_redirects WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListClientRedirects :many
SELECT * FROM client_redirects ORDER BY id;

-- name: DeleteClientRedirect :exec
DELETE FROM client_redirects WHERE id = sqlc.arg(id);

-- name: CreateClientRedirect :one
INSERT INTO client_redirects (client_id, redirect_uri) VALUES (sqlc.arg(client_id), sqlc.arg(redirect_uri)) RETURNING *;

-- name: UpdateClientRedirect :one
UPDATE client_redirects SET client_id = sqlc.arg(client_id), redirect_uri = sqlc.arg(redirect_uri) WHERE id = sqlc.arg(id) RETURNING *;

-- name: ClientRedirectsByClientId :many
SELECT * FROM client_redirects WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: GetClientAccessRule :one
SELECT * FROM client_access_rules WHERE client_id = sqlc.arg(client_id) AND group_id = sqlc.arg(group_id);

-- name: LockClientAccessRule :one
SELECT * FROM client_access_rules WHERE client_id = sqlc.arg(client_id) AND group_id = sqlc.arg(group_id) FOR UPDATE;

-- name: ListClientAccessRules :many
SELECT * FROM client_access_rules ORDER BY client_id,group_id;

-- name: DeleteClientAccessRule :exec
DELETE FROM client_access_rules WHERE client_id = sqlc.arg(client_id) AND group_id = sqlc.arg(group_id);

-- name: CreateClientAccessRule :one
INSERT INTO client_access_rules (client_id, group_id, priority, access_control) VALUES (sqlc.arg(client_id), sqlc.arg(group_id), sqlc.arg(priority), sqlc.arg(access_control)) RETURNING *;

-- name: UpdateClientAccessRule :one
UPDATE client_access_rules SET priority = sqlc.arg(priority), access_control = sqlc.arg(access_control) WHERE client_id = sqlc.arg(client_id) AND group_id = sqlc.arg(group_id) RETURNING *;

-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes WHERE id = sqlc.arg(id);

-- name: LockAuthorizationCode :one
SELECT * FROM authorization_codes WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListAuthorizationCodes :many
SELECT * FROM authorization_codes ORDER BY id;

-- name: DeleteAuthorizationCode :exec
DELETE FROM authorization_codes WHERE id = sqlc.arg(id);

-- name: CreateAuthorizationCode :one
INSERT INTO authorization_codes (client_id, user_id, session_id, token_hash, redirect_uri, pkce_challenge, pkce_method, scope, nonce, expires_at, consumed_at) VALUES (sqlc.arg(client_id), sqlc.arg(user_id), sqlc.arg(session_id), sqlc.arg(token_hash), sqlc.arg(redirect_uri), sqlc.arg(pkce_challenge), sqlc.arg(pkce_method), sqlc.arg(scope), sqlc.arg(nonce), sqlc.arg(expires_at), sqlc.narg(consumed_at)) RETURNING *;

-- name: UpdateAuthorizationCode :one
UPDATE authorization_codes SET client_id = sqlc.arg(client_id), user_id = sqlc.arg(user_id), session_id = sqlc.arg(session_id), token_hash = sqlc.arg(token_hash), redirect_uri = sqlc.arg(redirect_uri), pkce_challenge = sqlc.arg(pkce_challenge), pkce_method = sqlc.arg(pkce_method), scope = sqlc.arg(scope), nonce = sqlc.arg(nonce), expires_at = sqlc.arg(expires_at), consumed_at = sqlc.narg(consumed_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: AuthorizationCodesByClientId :many
SELECT * FROM authorization_codes WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: AuthorizationCodesByUserId :many
SELECT * FROM authorization_codes WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: AuthorizationCodesBySessionId :many
SELECT * FROM authorization_codes WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: AuthorizationCodeByTokenHash :one
SELECT * FROM authorization_codes WHERE token_hash = sqlc.arg(token_hash);

-- name: LockAuthorizationCodeByTokenHash :one
SELECT * FROM authorization_codes WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: GetOAuthToken :one
SELECT * FROM oauth_tokens WHERE id = sqlc.arg(id);

-- name: LockOAuthToken :one
SELECT * FROM oauth_tokens WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListOAuthTokens :many
SELECT * FROM oauth_tokens ORDER BY id;

-- name: DeleteOAuthToken :exec
DELETE FROM oauth_tokens WHERE id = sqlc.arg(id);

-- name: CreateOAuthToken :one
INSERT INTO oauth_tokens (client_id, user_id, session_id, code_id, family, access_token_hash, refresh_token_hash, scope, nonce, auth_time, access_expires_at, expires_at, revoked_at) VALUES (sqlc.arg(client_id), sqlc.arg(user_id), sqlc.arg(session_id), sqlc.arg(code_id), sqlc.arg(family), sqlc.arg(access_token_hash), sqlc.arg(refresh_token_hash), sqlc.arg(scope), sqlc.arg(nonce), sqlc.arg(auth_time), sqlc.arg(access_expires_at), sqlc.arg(expires_at), sqlc.narg(revoked_at)) RETURNING *;

-- name: UpdateOAuthToken :one
UPDATE oauth_tokens SET client_id = sqlc.arg(client_id), user_id = sqlc.arg(user_id), session_id = sqlc.arg(session_id), code_id = sqlc.arg(code_id), family = sqlc.arg(family), access_token_hash = sqlc.arg(access_token_hash), refresh_token_hash = sqlc.arg(refresh_token_hash), scope = sqlc.arg(scope), nonce = sqlc.arg(nonce), auth_time = sqlc.arg(auth_time), access_expires_at = sqlc.arg(access_expires_at), expires_at = sqlc.arg(expires_at), revoked_at = sqlc.narg(revoked_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: OAuthTokensByClientId :many
SELECT * FROM oauth_tokens WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: OAuthTokensByUserId :many
SELECT * FROM oauth_tokens WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: OAuthTokensBySessionId :many
SELECT * FROM oauth_tokens WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: OAuthTokenByAccessTokenHash :one
SELECT * FROM oauth_tokens WHERE access_token_hash = sqlc.arg(access_token_hash);

-- name: LockOAuthTokenByAccessTokenHash :one
SELECT * FROM oauth_tokens WHERE access_token_hash = sqlc.arg(access_token_hash) FOR UPDATE;

-- name: OAuthTokenByRefreshTokenHash :one
SELECT * FROM oauth_tokens WHERE refresh_token_hash = sqlc.arg(refresh_token_hash);

-- name: LockOAuthTokenByRefreshTokenHash :one
SELECT * FROM oauth_tokens WHERE refresh_token_hash = sqlc.arg(refresh_token_hash) FOR UPDATE;

-- name: GetSigningKey :one
SELECT * FROM signing_keys WHERE id = sqlc.arg(id);

-- name: LockSigningKey :one
SELECT * FROM signing_keys WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListSigningKeys :many
SELECT * FROM signing_keys ORDER BY id;

-- name: DeleteSigningKey :exec
DELETE FROM signing_keys WHERE id = sqlc.arg(id);

-- name: CreateSigningKey :one
INSERT INTO signing_keys (client_id, key, expires_at) VALUES (sqlc.arg(client_id), sqlc.arg(key), sqlc.arg(expires_at)) RETURNING *;

-- name: UpdateSigningKey :one
UPDATE signing_keys SET client_id = sqlc.arg(client_id), key = sqlc.arg(key), expires_at = sqlc.arg(expires_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: SigningKeysByClientId :many
SELECT * FROM signing_keys WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: GetTotpAuthenticator :one
SELECT * FROM totp_authenticators WHERE id = sqlc.arg(id);

-- name: LockTotpAuthenticator :one
SELECT * FROM totp_authenticators WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListTotpAuthenticators :many
SELECT * FROM totp_authenticators ORDER BY id;

-- name: DeleteTotpAuthenticator :exec
DELETE FROM totp_authenticators WHERE id = sqlc.arg(id);

-- name: CreateTotpAuthenticator :one
INSERT INTO totp_authenticators (user_id, name, secret, last_step, last_used_at) VALUES (sqlc.arg(user_id), sqlc.arg(name), sqlc.arg(secret), sqlc.arg(last_step), sqlc.narg(last_used_at)) RETURNING *;

-- name: UpdateTotpAuthenticator :one
UPDATE totp_authenticators SET user_id = sqlc.arg(user_id), name = sqlc.arg(name), secret = sqlc.arg(secret), last_step = sqlc.arg(last_step), last_used_at = sqlc.narg(last_used_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: TotpAuthenticatorsByUserId :many
SELECT * FROM totp_authenticators WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: GetWebauthnCredential :one
SELECT * FROM webauthn_credentials WHERE id = sqlc.arg(id);

-- name: LockWebauthnCredential :one
SELECT * FROM webauthn_credentials WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListWebauthnCredentials :many
SELECT * FROM webauthn_credentials ORDER BY id;

-- name: DeleteWebauthnCredential :exec
DELETE FROM webauthn_credentials WHERE id = sqlc.arg(id);

-- name: CreateWebauthnCredential :one
INSERT INTO webauthn_credentials (user_id, credential_id, name, credential, sign_count, last_used_at) VALUES (sqlc.arg(user_id), sqlc.arg(credential_id), sqlc.arg(name), sqlc.arg(credential), sqlc.arg(sign_count), sqlc.narg(last_used_at)) RETURNING *;

-- name: UpdateWebauthnCredential :one
UPDATE webauthn_credentials SET user_id = sqlc.arg(user_id), credential_id = sqlc.arg(credential_id), name = sqlc.arg(name), credential = sqlc.arg(credential), sign_count = sqlc.arg(sign_count), last_used_at = sqlc.narg(last_used_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: WebauthnCredentialsByUserId :many
SELECT * FROM webauthn_credentials WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: WebauthnCredentialByCredentialId :one
SELECT * FROM webauthn_credentials WHERE credential_id = sqlc.arg(credential_id);

-- name: LockWebauthnCredentialByCredentialId :one
SELECT * FROM webauthn_credentials WHERE credential_id = sqlc.arg(credential_id) FOR UPDATE;

-- name: GetRecoveryCode :one
SELECT * FROM recovery_codes WHERE id = sqlc.arg(id);

-- name: LockRecoveryCode :one
SELECT * FROM recovery_codes WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListRecoveryCodes :many
SELECT * FROM recovery_codes ORDER BY id;

-- name: DeleteRecoveryCode :exec
DELETE FROM recovery_codes WHERE id = sqlc.arg(id);

-- name: CreateRecoveryCode :one
INSERT INTO recovery_codes (user_id, hash, used_at) VALUES (sqlc.arg(user_id), sqlc.arg(hash), sqlc.narg(used_at)) RETURNING *;

-- name: UpdateRecoveryCode :one
UPDATE recovery_codes SET user_id = sqlc.arg(user_id), hash = sqlc.arg(hash), used_at = sqlc.narg(used_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: RecoveryCodesByUserId :many
SELECT * FROM recovery_codes WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: RecoveryCodeByHash :one
SELECT * FROM recovery_codes WHERE hash = sqlc.arg(hash);

-- name: LockRecoveryCodeByHash :one
SELECT * FROM recovery_codes WHERE hash = sqlc.arg(hash) FOR UPDATE;

-- name: GetMfaCeremony :one
SELECT * FROM mfa_ceremonies WHERE id = sqlc.arg(id);

-- name: LockMfaCeremony :one
SELECT * FROM mfa_ceremonies WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListMfaCeremonys :many
SELECT * FROM mfa_ceremonies ORDER BY id;

-- name: DeleteMfaCeremony :exec
DELETE FROM mfa_ceremonies WHERE id = sqlc.arg(id);

-- name: CreateMfaCeremony :one
INSERT INTO mfa_ceremonies (token_hash, user_id, actor_id, session_id, login_session_id, revision, purpose, state, expires_at, consumed_at, attempts) VALUES (sqlc.arg(token_hash), sqlc.arg(user_id), sqlc.arg(actor_id), sqlc.narg(session_id), sqlc.narg(login_session_id), sqlc.arg(revision), sqlc.arg(purpose), sqlc.arg(state), sqlc.arg(expires_at), sqlc.narg(consumed_at), sqlc.arg(attempts)) RETURNING *;

-- name: UpdateMfaCeremony :one
UPDATE mfa_ceremonies SET token_hash = sqlc.arg(token_hash), user_id = sqlc.arg(user_id), actor_id = sqlc.arg(actor_id), session_id = sqlc.narg(session_id), login_session_id = sqlc.narg(login_session_id), revision = sqlc.arg(revision), purpose = sqlc.arg(purpose), state = sqlc.arg(state), expires_at = sqlc.arg(expires_at), consumed_at = sqlc.narg(consumed_at), attempts = sqlc.arg(attempts) WHERE id = sqlc.arg(id) RETURNING *;

-- name: MfaCeremonyByTokenHash :one
SELECT * FROM mfa_ceremonies WHERE token_hash = sqlc.arg(token_hash);

-- name: LockMfaCeremonyByTokenHash :one
SELECT * FROM mfa_ceremonies WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: MfaCeremonysByUserId :many
SELECT * FROM mfa_ceremonies WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: MfaCeremonysBySessionId :many
SELECT * FROM mfa_ceremonies WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: GetForwardAuthRequest :one
SELECT * FROM forward_auth_requests WHERE id = sqlc.arg(id);

-- name: LockForwardAuthRequest :one
SELECT * FROM forward_auth_requests WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListForwardAuthRequests :many
SELECT * FROM forward_auth_requests ORDER BY id;

-- name: DeleteForwardAuthRequest :exec
DELETE FROM forward_auth_requests WHERE id = sqlc.arg(id);

-- name: CreateForwardAuthRequest :one
INSERT INTO forward_auth_requests (state_hash, browser_hash, code_hash, client_id, origin, return_uri, user_id, session_id, expires_at, consumed_at) VALUES (sqlc.arg(state_hash), sqlc.arg(browser_hash), sqlc.narg(code_hash), sqlc.arg(client_id), sqlc.arg(origin), sqlc.arg(return_uri), sqlc.narg(user_id), sqlc.narg(session_id), sqlc.arg(expires_at), sqlc.narg(consumed_at)) RETURNING *;

-- name: UpdateForwardAuthRequest :one
UPDATE forward_auth_requests SET state_hash = sqlc.arg(state_hash), browser_hash = sqlc.arg(browser_hash), code_hash = sqlc.narg(code_hash), client_id = sqlc.arg(client_id), origin = sqlc.arg(origin), return_uri = sqlc.arg(return_uri), user_id = sqlc.narg(user_id), session_id = sqlc.narg(session_id), expires_at = sqlc.arg(expires_at), consumed_at = sqlc.narg(consumed_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: ForwardAuthRequestByStateHash :one
SELECT * FROM forward_auth_requests WHERE state_hash = sqlc.arg(state_hash);

-- name: LockForwardAuthRequestByStateHash :one
SELECT * FROM forward_auth_requests WHERE state_hash = sqlc.arg(state_hash) FOR UPDATE;

-- name: ForwardAuthRequestByCodeHash :one
SELECT * FROM forward_auth_requests WHERE code_hash = sqlc.arg(code_hash);

-- name: LockForwardAuthRequestByCodeHash :one
SELECT * FROM forward_auth_requests WHERE code_hash = sqlc.arg(code_hash) FOR UPDATE;

-- name: ForwardAuthRequestsByClientId :many
SELECT * FROM forward_auth_requests WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: ForwardAuthRequestsByUserId :many
SELECT * FROM forward_auth_requests WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: ForwardAuthRequestsBySessionId :many
SELECT * FROM forward_auth_requests WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: GetForwardAuthSession :one
SELECT * FROM forward_auth_sessions WHERE id = sqlc.arg(id);

-- name: LockForwardAuthSession :one
SELECT * FROM forward_auth_sessions WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListForwardAuthSessions :many
SELECT * FROM forward_auth_sessions ORDER BY id;

-- name: DeleteForwardAuthSession :exec
DELETE FROM forward_auth_sessions WHERE id = sqlc.arg(id);

-- name: CreateForwardAuthSession :one
INSERT INTO forward_auth_sessions (token_hash, client_id, user_id, session_id, origin, expires_at) VALUES (sqlc.arg(token_hash), sqlc.arg(client_id), sqlc.arg(user_id), sqlc.arg(session_id), sqlc.arg(origin), sqlc.arg(expires_at)) RETURNING *;

-- name: UpdateForwardAuthSession :one
UPDATE forward_auth_sessions SET token_hash = sqlc.arg(token_hash), client_id = sqlc.arg(client_id), user_id = sqlc.arg(user_id), session_id = sqlc.arg(session_id), origin = sqlc.arg(origin), expires_at = sqlc.arg(expires_at) WHERE id = sqlc.arg(id) RETURNING *;

-- name: ForwardAuthSessionByTokenHash :one
SELECT * FROM forward_auth_sessions WHERE token_hash = sqlc.arg(token_hash);

-- name: LockForwardAuthSessionByTokenHash :one
SELECT * FROM forward_auth_sessions WHERE token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: ForwardAuthSessionsByClientId :many
SELECT * FROM forward_auth_sessions WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: ForwardAuthSessionsByUserId :many
SELECT * FROM forward_auth_sessions WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: ForwardAuthSessionsBySessionId :many
SELECT * FROM forward_auth_sessions WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: GetAuditLog :one
SELECT * FROM audit_logs WHERE id = sqlc.arg(id);

-- name: LockAuditLog :one
SELECT * FROM audit_logs WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs ORDER BY id;

-- name: DeleteAuditLog :exec
DELETE FROM audit_logs WHERE id = sqlc.arg(id);

-- name: CreateAuditLog :one
INSERT INTO audit_logs (user_id, event, data) VALUES (sqlc.arg(user_id), sqlc.arg(event), sqlc.arg(data)) RETURNING *;

-- name: UpdateAuditLog :one
UPDATE audit_logs SET user_id = sqlc.arg(user_id), event = sqlc.arg(event), data = sqlc.arg(data) WHERE id = sqlc.arg(id) RETURNING *;

-- name: AuditLogsByUserId :many
SELECT * FROM audit_logs WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: GetAccessLog :one
SELECT * FROM access_logs WHERE id = sqlc.arg(id);

-- name: LockAccessLog :one
SELECT * FROM access_logs WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListAccessLogs :many
SELECT * FROM access_logs ORDER BY id;

-- name: DeleteAccessLog :exec
DELETE FROM access_logs WHERE id = sqlc.arg(id);

-- name: CreateAccessLog :one
INSERT INTO access_logs (event_id, dedupe_key, client_id, user_id, session_id, source, data) VALUES (sqlc.arg(event_id), sqlc.arg(dedupe_key), sqlc.arg(client_id), sqlc.narg(user_id), sqlc.narg(session_id), sqlc.arg(source), sqlc.arg(data)) RETURNING *;

-- name: UpdateAccessLog :one
UPDATE access_logs SET event_id = sqlc.arg(event_id), dedupe_key = sqlc.arg(dedupe_key), client_id = sqlc.arg(client_id), user_id = sqlc.narg(user_id), session_id = sqlc.narg(session_id), source = sqlc.arg(source), data = sqlc.arg(data) WHERE id = sqlc.arg(id) RETURNING *;

-- name: AccessLogByEventId :one
SELECT * FROM access_logs WHERE event_id = sqlc.arg(event_id);

-- name: LockAccessLogByEventId :one
SELECT * FROM access_logs WHERE event_id = sqlc.arg(event_id) FOR UPDATE;

-- name: AccessLogByDedupeKey :one
SELECT * FROM access_logs WHERE dedupe_key = sqlc.arg(dedupe_key);

-- name: LockAccessLogByDedupeKey :one
SELECT * FROM access_logs WHERE dedupe_key = sqlc.arg(dedupe_key) FOR UPDATE;

-- name: AccessLogsByClientId :many
SELECT * FROM access_logs WHERE client_id = sqlc.arg(client_id) ORDER BY id;

-- name: AccessLogsByUserId :many
SELECT * FROM access_logs WHERE user_id = sqlc.arg(user_id) ORDER BY id;

-- name: AccessLogsBySessionId :many
SELECT * FROM access_logs WHERE session_id = sqlc.arg(session_id) ORDER BY id;

-- name: GetAccessLogDelivery :one
SELECT * FROM access_log_deliveries WHERE log_id = sqlc.arg(log_id);

-- name: LockAccessLogDelivery :one
SELECT * FROM access_log_deliveries WHERE log_id = sqlc.arg(log_id) FOR UPDATE;

-- name: ListAccessLogDeliverys :many
SELECT * FROM access_log_deliveries ORDER BY log_id;

-- name: DeleteAccessLogDelivery :exec
DELETE FROM access_log_deliveries WHERE log_id = sqlc.arg(log_id);

-- name: CreateAccessLogDelivery :one
INSERT INTO access_log_deliveries (log_id, attempts, next_attempt_at, delivered_at, last_error) VALUES (sqlc.arg(log_id), sqlc.arg(attempts), sqlc.arg(next_attempt_at), sqlc.narg(delivered_at), sqlc.arg(last_error)) RETURNING *;

-- name: UpdateAccessLogDelivery :one
UPDATE access_log_deliveries SET attempts = sqlc.arg(attempts), next_attempt_at = sqlc.arg(next_attempt_at), delivered_at = sqlc.narg(delivered_at), last_error = sqlc.arg(last_error) WHERE log_id = sqlc.arg(log_id) RETURNING *;

-- name: GetEventReportRate :one
SELECT * FROM event_report_rates WHERE client_id = sqlc.arg(client_id);

-- name: LockEventReportRate :one
SELECT * FROM event_report_rates WHERE client_id = sqlc.arg(client_id) FOR UPDATE;

-- name: ListEventReportRates :many
SELECT * FROM event_report_rates ORDER BY client_id;

-- name: DeleteEventReportRate :exec
DELETE FROM event_report_rates WHERE client_id = sqlc.arg(client_id);

-- name: CreateEventReportRate :one
INSERT INTO event_report_rates (client_id, window_start, count) VALUES (sqlc.arg(client_id), sqlc.arg(window_start), sqlc.arg(count)) RETURNING *;

-- name: UpdateEventReportRate :one
UPDATE event_report_rates SET window_start = sqlc.arg(window_start), count = sqlc.arg(count) WHERE client_id = sqlc.arg(client_id) RETURNING *;
