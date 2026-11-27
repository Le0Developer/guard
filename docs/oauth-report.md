# OIDC provider port

Implemented in `internal/app/oauth.go`, with protocol boundary tests in `oauth_test.go` and PostgreSQL lifecycle tests in `oauth_integration_test.go`. Added four sqlc queries in `sql/queries/oauth.sql`; root regenerated the generated API.

Routes preserve the Rust provider's per-client issuer, discovery and JWKS URLs, shared authorize/token/userinfo/revoke endpoints, and noncredentialed CORS. Discovery includes the root-owned event endpoint. ForwardAuth authorization dispatches to the root-owned handler. No event handler is registered here.

Authorization rejects duplicate parameters, unregistered or malformed redirect URLs, unsupported scope/response modes/request objects/prompts, malformed PKCE, and invalid max_age. Prompt login and max_age force login while removing those fields from the continuation. Prompt none returns login_required without a login redirect. Scope and nonce survive code redemption; state survives authorization errors and successful callbacks.

Client authentication supports URL-decoded Basic credentials and POST credentials, with mixed or repeated methods rejected. Opaque code/access/refresh credentials are hashed before persistence. Code redemption and refresh rotation lock the client row before reading grants, then lock the grant row. This serializes all family mutations, including refresh replay against concurrently created descendants. Replay records revocation and audit within the successful transaction, then returns invalid_grant after commit. Revocation revokes the entire family. A wrong PKCE verifier does not consume the code.

Every successful authorization, exchange, refresh, and userinfo operation checks current user/session validity and current client group access. Access and refresh expiry are capped by the login session and configured client lifetime. Refresh cannot expand scopes or extend its original lifetime.

RSA-2048 private keys are stored as PKCS#1 DER in PostgreSQL. Creation is serialized with the client row lock, including JWKS first-use. Keys rotate before their remaining lifetime drops below the maximum access-token lifetime; JWKS retains unexpired old public keys. JWTs use stdlib RS256, include issuer/audience/subject/auth_time and scope-limited profile/email claims, and preserve nonce.

Tests written before implementation: duplicate field and PKCE boundaries. Initial execution was blocked by sandbox access to default Go caches. Using writable `/tmp/guard-go-cache` and `/tmp/guard-go-mod` removes that environmental problem. Subsequent package test runs initially hit other workers' incomplete admin/ForwardAuth methods. Once shared code compiled, all six OAuth boundary tests passed. Local PostgreSQL TCP access required escalation outside the network sandbox. The authorized escalated run passed all 13 OAuth tests, including seven real PostgreSQL lifecycle tests, in 1.173 seconds.

Integration coverage includes RFC 7636 vector and verifier boundaries, malformed/duplicate form inputs, mixed client authentication, claim scope limits, wrong PKCE then successful redemption, independent RSA signature verification, code replay revocation, concurrent refresh replay and descendant revocation, explicit revocation, deleted session rejection, prompt handling, malicious callback rejection, POST client authentication, disabled users, current permission changes, and refresh scope reduction/expansion.

Focused validation command: `GOCACHE=/tmp/guard-go-cache GOMODCACHE=/tmp/guard-go-mod GUARD_TEST_DATABASE_URL=postgres://leodev@localhost:55439/postgres?sslmode=disable go test ./internal/app -run TestOAuth -count=1 -v`. All 13 tests passed. Root separately reported the full real-PostgreSQL integration suite passing in 2.186 seconds. Root owns final race/vet/build verification.

Final protocol review checked client authentication ambiguity, exact callback matching, PKCE verifier enforcement, prompt/max_age continuation handling, refresh scope reduction, family/code replay revocation ordering, key rollover overlap, JWT issuer/audience/nonce, and current user/session/group access. No known blocking protocol defect remains. Client-row serialization intentionally trades per-client grant throughput for straightforward family-wide replay correctness.

Detailed access journaling uses the root-owned best-effort `recordAccess` helper for authorize/token/refresh/userinfo/revoke outcomes and known-client denials. It records endpoint path, status and decision, without raw query parameters, codes, access/refresh tokens, state, nonce or secrets.
