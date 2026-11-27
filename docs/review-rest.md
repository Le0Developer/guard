# Independent final review: administration, ForwardAuth, journal, deployment

Reviewed the design requirements and the application/admin/ForwardAuth/journal code, migration/schema, command and deployment files. No broad test suites were rerun. The two findings below are resolved after scoped re-review of the fixes.

## Resolution and final verdict

Scoped re-review inspected `response.go`, `journal.go`, `forward.go`, `oauth.go`, and `persistence_regression_test.go`. No unresolved material defects were found in these fixes.

`recordAccess` now returns persistence failures. OAuth and ForwardAuth buffer responses before releasing them, and journal failure replaces the buffered response with 503 while clearing credentials, redirects, cookies and identity headers. Discovery/JWKS identify their client for logging, and successful ForwardAuth callbacks also persist their access record before releasing the new cookie.

The central ForwardAuth adapter now converts callback redirects through `/auth_request` to 401, preserves Location, and forwards only the first Set-Cookie. Regression tests cover both access-log and outbox INSERT failure for OAuth/ForwardAuth and the complete nginx-style initiation, authorization, callback and cookie-verification sequence. The parent agent reports reproducing the original failures and passing these focused real-PostgreSQL tests after the fixes; this re-review inspected their assertions without rerunning tests.

The original findings are retained below as review history.

## Resolved P1: Access journal persistence errors permit successful authorization

Location: `internal/app/journal.go:55-57`; callers include `internal/app/forward.go` and `internal/app/oauth.go:136`.

`recordAccess` logs a failed transaction and returns no error. With detailed logging enabled, failure to insert an access event or its delivery row still allows ForwardAuth to return 200 and allows OAuth responses to reach the browser/client. The OAuth wrapper records after the real response has already been committed, so simply changing the helper signature is insufficient there.

Scenario: keep authentication tables readable but deny INSERT on `access_logs`/`access_log_deliveries`, or inject an insert failure. A valid ForwardAuth cookie still receives 200 without its required access record. This contradicts the design's fail-closed persistence requirement and Rust `src/journal.rs`, which replaces the response with 503 (`access_journal_unavailable`) on journal failure.

Fix: return persistence failures, buffer OAuth responses until required journal persistence succeeds, and emit 503 instead of the successful response on failure. Add failure-injection coverage for both ForwardAuth and OAuth and for delivery-row insert failure.

## Resolved P1: Nginx auth_request callback returns an unsupported redirect status

Location: `internal/app/forward.go:347-350` (compare the initial-login adaptation at lines 400-404).

The callback unconditionally sets both cookies and returns 303. When a proxy sends the original callback URL through `/auth_request` using `X-Forwarded-Uri`, the callback branch runs and returns 303 to the auth subrequest. Nginx auth_request accepts 2xx, 401 and 403; 303 produces an unexpected-status error/500 instead of the external redirect adapter running. The flow is already consumed, making retrying the callback fail too.

Rust `src/server/forwardauth.rs::no_store` converts every auth_request redirect, including callbacks, to 401, preserves Location, and retains only the first Set-Cookie (the new app-session cookie) because the nginx adapter exposes one cookie value. The Go special handling covers only initiation.

Fix: centralize auth_request response adaptation or apply the same 401/Location/one-cookie behavior to callback success. Add an end-to-end handler regression covering initiation, authorization, callback through `/auth_request`, the new cookie, and the eventual 200 verification.
