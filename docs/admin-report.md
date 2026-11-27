# Administration port report

Implemented in internal/app/admin*.go and sql/queries/admin.sql. Root regenerated sqlc output; no generated, schema, asset, or shared application files were edited by this worker.

## Behavior

All Rust administration routes are registered with explicit HTTP methods and administrator authorization. Global middleware supplies session authentication and CSRF validation. The dedicated MFA worker owns /admin/users/{id}/security.

Administration includes searchable user/group/client lists, create/edit forms, overview counts, confirmation screens, user password reset and role changes, self-disable/delete/role-change protections, individual and complete session revocation, soft deletion, group membership, client credentials and endpoints, secret rotation with explicit confirmation, exact callback registration and editing/removal, strict canonical ForwardAuth origins, PKCE/lifetime/logging controls, and access-rule upserts/removal.

Writes use transactions and row locks. User security changes revoke sessions (cascading OAuth/ForwardAuth credentials), invalidate MFA revisions, and delete ceremonies. Full generated user/client updates preserve all unrelated fields. New users receive random stable WebAuthn handles. Redirect ownership checks prevent cross-client mutations; callbacks retain the exact validated input. ForwardAuth origin registration is intentionally strict: paths and query strings are rejected by the shared Origin helper. Client-type changes to ForwardAuth reject incompatible existing callback URLs.

Successful mutations write audit entries atomically; rejected authenticated POSTs write sanitized audit outcomes. Passwords, secrets, raw URLs, and submitted strings are excluded from administration audit metadata. Logging-flag changes also create configuration journal events and collector outbox records inside the transaction using the shared persistAccess helper.

Audit/access views use descending typed cursors and 100-record pages. The access view supports client/session/source filters and displays delivery status, aggregate pending/retry counts, and escaped JSON details. Names and submitted values are rendered with html/template. Existing CSS classes are reused without asset changes.

## Verification

Initial test run was red at compilation because registerAdmin and redirect validation were absent (shared foundation implementation was also still in progress). After implementation, sandbox network restrictions blocked PostgreSQL access; the authorized escalated run succeeded:

`GUARD_TEST_DATABASE_URL=postgres://leodev@localhost:55439/postgres?sslmode=disable GOCACHE=/private/tmp/guard-go-cache GOMODCACHE=/private/tmp/guard-go-mod go test ./internal/app -run TestAdmin -count=1`

Result: PASS, 0.441s. Tests cover unauthenticated/non-admin authorization, invalid redirect boundaries, complete persisted user/group/client lifecycle and rendered pages, separate role/password actions, stale role confirmations, session invalidation and MFA revision changes, idempotent membership, exact callback storage, allow/deny rules, rotation confirmation, cross-client redirect ownership, self-delete/self-disable rejection, soft-delete visibility, membership cleanup, and audits. Root independently reported the full PostgreSQL integration suite passing (2.186s).

## Limits and review notes

No automated browser screenshot comparison was performed. Layout uses existing page structure/classes but is not a byte-for-byte Rust template copy. Forms return clear 422 errors for invalid input instead of redisplaying every submitted field inline. Rule editing is available through add-or-replace selection rather than individual prefilled row forms. Journal views expose escaped structured details rather than reproducing all Rust summary columns.

Application-level case-insensitive group-name checks require a database partial unique index to guarantee uniqueness under concurrent creation; this schema concern was reported to root (schema ownership is outside this worker). Audit/access pages fetch a bounded event page, but entity choice lists intentionally load all users/groups/clients as the existing implementation did. Physical WebAuthn verification remains with the MFA/browser validation work.
