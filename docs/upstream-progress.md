# Upstream provider implementation record

User requested incoming upstream back-channel logout, database-backed OIDC setup with UI, removal of OIDC environment settings, and daily JWKS caching. All changes are in go/; runtime dependencies remain pgx and WebAuthn only.

Implemented provider discovery/admin CRUD at /admin/providers, write-only secret edits, enabled/PKCE/signing-alg/logout settings, callback/logout URLs, immediate DB-driven login choices and offline editing of existing configuration. Removed the old provider Config/Provider types and OIDC environment loader/example settings. Provider edits/deletion revoke derived Guard sessions and pending logins.

Upstream sign-in now validates a signed ID token with exact issuer/audience/nonce/time/pinned algorithm and cross-checks userinfo sub plus verified-email account matching. A persisted pending binding retains the matched local user/email, signed upstream subject/sid, provider revision and issuance time through MFA; finalization rechecks account/email uniqueness under the user row lock. Accepted Guard sessions retain their upstream binding.

POST /login/{method}/backchannel-logout validates the signed logout JWT and issuer/audience/time/jti/events/sub/sid rules with no nonce. It atomically records replay/watermark state, revokes only matching provider-derived sessions/pending MFA, audits revocation and queues existing downstream notifications through cascading session deletion. Replays succeed idempotently. Logout watermarks prevent delayed callbacks resurrecting ended sessions; 503 distinguishes storage/key availability failures from invalid400 requests.

JWKS cache is per provider/config revision with a 24-hour on-demand TTL. Unknown kid may refresh early with a ten-second throttle. Refreshes use per-provider in-flight coordination, release the map lock before HTTP, and honor cancellation; slow providers cannot block unrelated cached/new-provider validation. Endpoints are pinned, responses bounded, redirects disabled. Unknown-key refresh throttling returns503 for legitimate rotation retry. Supplied empty identity claims and duplicate JSON members are rejected.

Independent review found two important gaps: stale matched-account binding through MFA and global JWKS network locking. Both were reproduced by regression tests, fixed, and re-reviewed as resolved. Daily cache test also demonstrated red with old five-minute TTL and green at24h. Scope covers all ten supported RSA/PSS/ECDSA/EdDSA signature algorithms.

Validation: full non-race PostgreSQL suite passed (app9.275s); vet/build/sqlc vet passed and regeneration unchanged. Browser login and new provider form checked at desktop and375px widths; narrow admin navigation wrapping corrected. Final race output recorded below after completion.

Documentation: README.md upstream-login section is current; old OIDC environment values are ignored and are not imported. No migration from Rust data or environment credentials. No changes or deployment outside go/.

Final complete `go test -race ./... -count=1` against PostgreSQL passed (app66.440s, security4.267s). Independent review confirmed both findings resolved. No new dependencies, commits or deployment. Temporary preview/database stopped after checks.
