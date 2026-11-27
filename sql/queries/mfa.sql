-- name: MFABumpRevision :exec
UPDATE users SET mfa_revision=mfa_revision+1 WHERE id=$1;
-- name: MFAFailure :exec
UPDATE users SET mfa_failures=CASE WHEN mfa_window > now()-interval '5 minutes' THEN mfa_failures+1 ELSE 1 END,mfa_window=CASE WHEN mfa_window > now()-interval '5 minutes' THEN mfa_window ELSE now() END WHERE id=$1;
-- name: MFAResetFailures :exec
UPDATE users SET mfa_failures=0,mfa_window=NULL WHERE id=$1;
-- name: MFAAttempt :exec
UPDATE mfa_ceremonies SET attempts=attempts+1 WHERE id=$1;
-- name: MFAConsume :exec
UPDATE mfa_ceremonies SET consumed_at=now() WHERE id=$1;
-- name: MFADeleteCeremonies :exec
DELETE FROM mfa_ceremonies WHERE user_id=$1;
-- name: MFARevokeSessions :exec
DELETE FROM sessions WHERE user_id=$1 AND id<>sqlc.arg(keep_session);
-- name: MFADeleteRecovery :exec
DELETE FROM recovery_codes WHERE user_id=$1;
-- name: MFADeleteTOTP :exec
DELETE FROM totp_authenticators WHERE user_id=$1;
-- name: MFADeleteKeys :exec
DELETE FROM webauthn_credentials WHERE user_id=$1;
