# Go replacement progress

Completed in go/ as requested. Fresh PostgreSQL; Rust source and pre-existing edits untouched. No commits, merge, push or deployment.

Implemented: embedded schema/migrations, distinct ID types and sqlc column overrides, stdlib configuration/crypto/password sessions/CSRF/proxy-aware throttling, upstream providers, OIDC provider, MFA, administration, private ForwardAuth, audit/access journals, application event API, collector outbox/retries, cleanup, deployment templates and README.

Validation on 2026-11-24:
- go test ./... with real PostgreSQL: PASS (3.351s before final additional software-WebAuthn coverage).
- Final go test -race ./... with real PostgreSQL: PASS (app 26.497s, security 4.241s), including all later tests.
- go vet ./...: PASS.
- go build ./cmd/guard: PASS.
- sqlc vet: PASS; sqlc generate produces identical files.
- Browser login/logout, admin/security pages and layout: PASS.
- Independent auth/rest review findings fixed and regression-tested red/green: HMAC upstream state/private verifier; canonical MFA reauth return; journal fail closed with buffered responses; nginx callback adaptation. Scoped re-review confirmed journal/ForwardAuth fixes.
- Browser additionally exposed referrer-policy/Origin conflict on native form POST; regression and same-origin policy fix confirmed in browser.
- Case-insensitive active group-name uniqueness enforced by PostgreSQL index.
- Software WebAuthn authenticator test verifies actual P-256 enrollment/assertion signatures, counter persistence and replay rejection.

Limits: physical security-key interoperability and Docker image builds were not exercised in this environment. TOTP enrollment supplies manual secret/otpauth link instead of QR. Nested workflow is a template until moved into the repository root workflow directory.

References checked: sqlc column overrides (https://docs.sqlc.dev/en/latest/howto/overrides.html), go-webauthn API/package source, browser referrer-policy behavior (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).
