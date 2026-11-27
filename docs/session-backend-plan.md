# Backend session lifecycle

User approved token introspection instead of iframe session management, and requested back-channel logout. Implement in go/ only with existing dependency/typed-ID constraints.

Design: authenticated POST /oauth2/introspect, client-scoped access and refresh token checks, active=false for unknown/expired/revoked/unauthorized tokens; storage failures return503. Discovery advertises introspection endpoint/auth methods. No iframe or browser polling implementation. Applications choose their poll/cache interval.

Back-channel logout: configurable per-OIDC-client HTTPS endpoint (HTTP loopback allowed for development), optional session-required metadata. Include an opaque per-client/per-Guard-session sid in ID tokens. Persist RP participation independently of short-lived access tokens. A PostgreSQL trigger on participation deletion atomically queues logout delivery when Guard sessions are deleted by any path, including admin/MFA revocation and expiry. Stable sid and jti identify session/event across retries. Delivery worker claims a 30-second durable lease and releases database locks before HTTP. Lease-token conditions protect against stale workers. Delivery worker signs RS256 logout JWTs with client signing keys and iss/aud/iat/exp/jti/sub/sid/events, never nonce; sends form logout_token, no redirects, retries failures with backoff. Retain pending deliveries through restart. Retired/reconfigured endpoints cancel queued deliveries; no logout payload delivered to a replacement endpoint. Deliveries expire after a bounded retry window and remain inspectable in database.

Tasks:
1. Root: migrations, typed IDs/sqlc, RP tracking and sid issuance, atomic logout outbox, signing/sending/retry worker, expiry scheduling.
2. Introspection: handler/registration/discovery and protocol/database failure tests.
3. Client configuration: validation, admin form/save/preservation tests, documentation for client-side polling and logout JWT validation.
4. Integration/review: real PostgreSQL session lifecycle, signed JWT validation, callback failures/retries/concurrency, logout/admin/MFA/expiry paths; race/vet/build/sqlc reproducibility and independent review.

Interfaces: Client.BackchannelLogoutUri string, Client.BackchannelLogoutSessionRequired bool; db.SetClientBackchannelLogout(ctx,params) returns Client; a.oauthSID(ctx,q,client,identity) (string,error); a.deliverLogoutBatch(ctx) error. Root owns migrations, generated code, sqlc config, ids, oauthMint changes and background loop. Other workers own disjoint handlers/UI files.
