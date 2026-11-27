# Guard Go replacement

User-approved direction: complete replacement in a subdirectory, fresh PostgreSQL database, preserve the Rust application while developing the replacement.

Preserve password and upstream OIDC login, 18-hour sessions, CSRF protection, proxy-aware login throttling, administration of users/groups/clients and access rules, OIDC code/PKCE/refresh/revocation/discovery/JWKS/userinfo, private ForwardAuth, TOTP/security keys/recovery codes, audit and access records, application reports, collector delivery, and expiry cleanup. Port the working tree, including uncommitted password/provider work. Preserve existing routes and assets where practical.

Architecture: one Go binary, net/http ServeMux, html/template, embed, log/slog; PostgreSQL with pgx/v5 and checked-in sqlc-generated queries; go-webauthn for WebAuthn. All other direct runtime functionality uses stdlib. Indirect dependencies of pgx and WebAuthn are permitted. Passwords use salted PBKDF2-HMAC-SHA256; encrypted TOTP uses AES-GCM. No legacy data import or bcrypt compatibility. No UI redesign.

Every entity has a distinct defined int64 ID type; foreign keys use that entity's type via sqlc column overrides, including nullable pointers. No aliases, generic int IDs, or manually maintained generated database code. Numeric counters/revisions/timestamps are not IDs.

Alternatives considered: complete replacement versus gradual Rust/Go coexistence. User chose complete replacement; only the source trees coexist. New Go deployment uses PostgreSQL and does not share Rust SQLite data. Use explicit transactions and row locks for one-use grants, recovery codes, MFA ceremonies, refresh rotation, and replay handling. Restrict redirects and origins, validate browser binding, expire sessions and child credentials, fail closed on persistence errors.

Validation: unit tests for crypto and input boundaries; real PostgreSQL integration tests for transactions, sessions, routes, administration and protocol grants; go test -race, go vet, sqlc regeneration, build. Deployment artifacts and usage instructions live in go/. Physical security keys require manual browser verification where an authenticator is unavailable.
