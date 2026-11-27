# Go replacement implementation plan

Goal: ship a complete, independently runnable Go replacement in go/.
Spec: design.md. All changes stay inside go/; preserve pre-existing working-tree changes.

## Tasks
1. Foundation: schema, strongly typed IDs, sqlc queries, migrations, configuration, crypto, sessions, middleware, password/upstream login and shared rendering. Write boundary tests first, run failing tests, implement, run passing tests.
2. OIDC provider: discovery, signing keys, authorization/PKCE, token exchange, refresh rotation/replay, userinfo and revocation. Test protocol validation and real database grant lifecycle.
3. MFA: TOTP enrollment, encrypted secrets, replay prevention, recovery codes, WebAuthn ceremonies and administrative management. Test known vectors, ceremony binding/expiry and one-use credentials.
4. Administration: current user/group/client management, confirmations, access rules, redirects, session revocation and audit views. Test authorization, CSRF, invalid inputs and persisted changes.
5. ForwardAuth and journals: origin registration, browser-bound redirects, one-use completion, application sessions, logging, reporting, delivery and cleanup. Test malicious origins, state binding, replay and revocation.
6. Integration: deployment files, documentation, integration tests, race/vet/build/sqlc reproducibility; independent review then fix important findings.

Shared interface: internal/app.App owns Pool *pgxpool.Pool, Q *db.Queries, Config Config, HTTP *http.Client. Handlers use a.user(r), a.requireUser(w,r), a.requireAdmin(w,r), a.page(w,r,title,templateText,data), a.fail(w,r,status,message), a.audit(ctx,q,userID,event,data), a.permitted(ctx,q,clientID,userID), security helpers, and db generated models. Each worker owns its dedicated app files and test files, and may add SQL in a dedicated queries file. Root owns shared/schema/generated files.

Review focus: concurrent replay; disabled/deleted users and stale sessions; cross-user MFA administration; redirect/origin/header ambiguity; partial writes and database errors.
