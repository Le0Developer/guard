# Authentication review

Independent static review of `docs/design.md`, authentication handlers, security primitives, MFA browser integration, OAuth grants, schema, query definitions, ID overrides, and relevant Rust behavior. No implementation files changed and no broad tests rerun.

## Material findings

1. **P2 — Public upstream state discloses the PKCE verifier.** `internal/app/login.go:83` places `login.InternalToken` in the authorization URL's `state`; `login.go:286` sends that same value as `code_verifier`. The upstream authorization response echoes state alongside the code. A party obtaining that response therefore obtains both code and verifier, defeating the additional interception protection PKCE is intended to provide. The client secret remains a separate defense, so this is not a standalone account takeover claim. Rust deliberately derives state with a domain-separated HMAC keyed by the internal token. Restore independent state (or the Rust HMAC construction), compare that derived state in the callback, and keep the verifier server-side until token exchange. Add a regression assertion that public state differs from the verifier and cannot be used to satisfy the advertised S256 challenge.

2. **P2 — Reauthentication from a stale management form returns to a POST-only route.** `internal/app/mfa.go:135` uses `r.URL.Path` as the post-login redirect for every non-key management request. Open `/security`, leave it open beyond the five-minute management window, then submit Add authenticator, replace backup codes, rename, remove, or reset: authentication succeeds but redirects the browser with GET to `/security/totp`, `/security/backup-codes`, etc. Those paths only register POST handlers (`mfa.go:124`), producing 405 instead of returning to usable security settings. Use the canonical GET management base (`/security`, `/account/security`, or the appropriate admin target security page) as the reauthentication destination, without replaying the mutation. Verify at least one stale self-management form and one admin target form.

## Optional improvements, not release-blocking findings

- Upstream provider URL validation accepts remote HTTP, as Rust already does. Requiring HTTPS outside loopback would prevent deployment mistakes from exposing provider secrets and bearer tokens, but is existing configuration policy rather than a newly introduced parity bug.
- `mfaContext` rejects explicit target ID zero even though the bootstrap system user has ID zero. Self-management through `/security` still works, and the separate admin route policy already excludes system user management; treat any change here as an explicit product policy decision.

## Other observations

The inspected schema uses distinct ID definitions and sqlc column overrides, including nullable identity pointers. MFA code/recovery verification serializes on the account row, persists failed attempts, checks browser/login binding, and consumes challenges. Grant rotation and replay revocation use explicit transactions. No additional concrete material defect was established in those paths during this review. Physical WebAuthn success still needs the separately documented manual browser verification.
