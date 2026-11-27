# Independent backend session review

Reviewed the backend session plan, introspection handler and authentication helpers, back-channel signing and delivery worker, logout URL validation, discovery and SID issuance, client configuration and views, background cleanup, migration 003, outbox queries, typed-ID overrides, and relevant lifecycle/concurrency tests.

## Findings

No concrete critical or important security/correctness defect found in the reviewed implementation.

The persisted claim lease releases the delivery/client locks before network I/O, allowing a recipient to fetch Guard's JWKS during its callback. Claim selection uses `FOR UPDATE SKIP LOCKED`; completion, cancellation, and rescheduling require the current lease token, preventing an expired worker from overwriting a subsequent worker's result. The HTTP deadline is shorter than the lease, and crash recovery remains at-least-once.

Introspection authenticates confidential OIDC clients before returning token information, scopes results to the authenticated client, checks access/refresh expiry and revocation plus current Guard identity and authorization, and maps database failures to 503. Unknown and unauthorized tokens produce only `active:false`.

ID tokens receive a persisted per-client/per-Guard-session opaque SID. Logout JWTs use the existing client signing-key path and contain the required claims/events without nonce. Session deletion cascades through participation deletion into the transactional outbox; endpoint snapshots prevent delivery to replacement endpoints. Delivery uses form POST, disables redirects, recognizes only 200/204 as success, permanently cancels other nonrecoverable HTTP statuses, backs off recoverable failures, and bounds the delivery window to 24 hours.

## Verification limits and follow-up coverage

This was a source/test review, not a new test execution; no broad rerun was performed. The parent implementer owns the final suite after the lease improvement. Existing concurrency tests exercise simultaneous claims and reentrant JWKS fetching. Additional focused coverage for an abandoned lease being reclaimed and for an old lease holder attempting completion after reclamation would strengthen regression protection, although the SQL token predicates implement the expected protection.

An endpoint configuration change after a claim has committed may race an already starting request. This is an ordinary in-flight delivery boundary; the worker validates the snapshotted endpoint at claim time and never substitutes the replacement endpoint. No stronger immediate cancellation guarantee is claimed here.
