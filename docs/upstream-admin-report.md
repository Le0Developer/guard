# Upstream provider administration

Implemented `App.registerUpstreamAdmin(*http.ServeMux)` with admin-only list, create, edit and soft-delete routes under `/admin/providers`. Root registers this beneath the existing global CSRF middleware and adds navigation.

Creation discovers metadata from the exact issuer. Issuer changes and the explicit refresh checkbox discover again; unchanged issuers use persisted endpoints so offline providers can be disabled, edited or deleted. Discovery retains issuer paths, forbids redirects, limits responses to 1 MiB with a 15-second timeout, rejects issuer mismatches and missing algorithm metadata, and validates every endpoint as HTTPS or loopback HTTP. Discovery only requests the public configuration endpoint and sends no credentials.

Slug is permanent, lowercase and URL-safe; password/mfa are reserved. UI includes credentials, scopes, PKCE, pinned signing algorithm, enabled and back-channel logout settings, plus callback/logout configuration URLs. Secrets are write-only: blank edits preserve them, and the view receives an explicitly redacted provider. Audit entries contain only action, typed target ID and status. No provider object or secret is serialized into an audit entry.

Edits and deletes lock the provider and revoke provider-derived sessions and pending logins in the same audited transaction. Edits reject a concurrent revision change; delete remains possible while a provider is disabled or offline. The UI explains revocation before saving.

Tests cover discovery URL/metadata rejection, path preservation, missing algorithms, redirects and response bounds; admin authorization, global CSRF, create/edit/delete, secret redaction/preservation, offline editing, provider-session and pending-login revocation. Initial test invocation demonstrated the expected missing-discovery compile failure. Isolated discovery tests pass using the discovery implementation, discovery tests, existing URL validator and a minimal App/error stub in a temporary directory. Final integration verification awaits root's in-progress login/config migration, which currently causes unrelated compilation failures.
