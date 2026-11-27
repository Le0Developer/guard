# Database upstream OIDC and inbound back-channel logout

User requested upstream back-channel logout and moving all upstream OIDC setup from environment variables into PostgreSQL with admin UI. Existing runtime dependency limit and typed IDs remain. Work stays in go/.

Implement providers with a stable slug, display name, exact issuer, pinned signing algorithm, discovery-derived authorization/token/userinfo/JWKS endpoints, confidential client ID/secret, scopes, PKCE and enabled/logout toggles. No OIDC_* environment loading or automatic environment import. Settings take effect immediately. Secrets are never rendered or audited. Provider configuration changes revoke provider-derived sessions and pending logins. Keep local password/bootstrap login available according to existing PASSWORD_DISABLED setting.

Validate upstream ID tokens using pinned issuer/audience/algorithm and configured JWKS, nonce/iat/exp; require userinfo sub to match signed sub, preserving verified-email matching to one active local account. Persist matched local user/email and provider/subject/sid/revision/ID-token iat through MFA and into issued Guard sessions. Retain logout event watermarks to prevent a delayed callback or pending MFA login from resurrecting an upstream session after logout. Serialize finalization/logout/config edits on the provider row.

Accept form POST /login/{method}/backchannel-logout without browser cookie/CSRF. Verify signed logout token against provider keys (no untrusted jku/x5u), issuer/audience/time/jti/events and sub and/or sid, prohibit nonce, reject ID-token substitution, persist replay identity and delete only matching provider-derived Guard sessions/pending logins transactionally. Repeated valid logout succeeds idempotently. Deleting Guard sessions cascades token revocation and downstream back-channel outbox through existing triggers. Storage failures503, invalid requests400, no tokens/secrets in diagnostics.

Tasks: root schema/sqlc/provider types, login/session-binding conversion, inbound endpoint/watermarks/integration tests; JWT specialist verification/JWKS cache and boundary tests; admin specialist provider CRUD/discovery/validation/secret UI and tests; root config/env/docs cleanup, complete PostgreSQL/race/vet/build/sqlc checks and independent review.

Shared interfaces: db.UpstreamProvider; a.verifyUpstreamJWT(ctx,p,raw,purpose,nonce) (upstreamClaims,error); a.registerUpstreamAdmin(mux); a.discoverUpstream(ctx,issuer) (upstreamDiscovery,error); a.provider(ctx,slug) (db.UpstreamProvider,error). Root owns schema/generated/ids/login/http/config/app fields. Admin owns new admin_upstream*.go and upstream_discovery.go; JWT specialist owns upstream_jwt*.go. Cross-feature changes agreed via messages.

User follow-up: JWKS TTL24hours; unknownkid can refresh earlier with10secondthrottle; providerrevision invalidates cache; perprovider fetches do not block unrelated providers.
