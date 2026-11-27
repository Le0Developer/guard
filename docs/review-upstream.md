# Independent upstream OIDC review

Reviewed the DB provider lifecycle, callback/session binding, inbound logout, JWT/JWKS handling, migration 004, SQL queries and MFA handoff by source inspection. No source changes or broad test runs were performed. Concurrent JWT/discovery hardening was in progress during review; the already assigned empty-claim and unknown-key fixes are excluded below.

## Resolved: preserve the verified local-account match through MFA

Re-review: the pending binding now persists typed local `UserID` and `MatchedEmail`. `finishLogin` verifies both against the locked local user and rechecks exactly one active email match before creating a session. This closes the callback and pending-MFA scenarios below. `TestUpstreamMFARechecksMatchedAccount` covers email changes and newly ambiguous matches. The implementing agent reports observing both fail before the fix and pass afterward; this reviewer inspected the regression and implementation without independently running the database suite.

Locations: `internal/app/upstream.go:71-88`, `internal/app/login.go:225-239`, `internal/app/admin_users.go:109-122`, migration 004 `upstream_pending_logins`.

The verified email is matched to a local user only in the callback. `saveUpstreamBinding` accepts that user but never uses it, and the pending binding saves neither matched user nor matched email. Session finalization checks disabled/deleted/MFA revision only. Ordinary admin email edits do not increment that revision.

Reproduction: start upstream login for local user U, reach MFA, change U's email in the admin UI, then finish MFA. MFA loads the updated user and issues a session for U even though the upstream verified email no longer matches U. The no-MFA path has the same issue in the shorter lookup-to-finalization race. This matters when an administrator changes an email to remove an old upstream identity's access.

Fix: persist the matched local user and verified email (or a dedicated account-binding revision) in the upstream pending record and validate them while holding `LockUser` at final issuance. Email changes should invalidate affected pending upstream authentications, including existing MFA ceremonies, or bump the revision captured by those authentications. Merely comparing the current user with the user returned by `mfaLoad` does not fix the pending-MFA case. Add a regression covering an admin email change after primary authentication and before MFA completion.

## Resolved: one JWKS fetch blocks all upstream providers

Re-review: network requests now execute outside the global cache mutex. A per-entry completion channel coordinates concurrent refreshes, waits honor request cancellation, and active refresh entries cannot be evicted. Cached validation for another provider can proceed independently. `TestUpstreamJWKSProviderIsolation` covers the previously blocked-provider scenario; the implementing agent reports a red/green run including race detection.

The user's subsequent daily-cache requirement is implemented as a 24-hour on-demand TTL. Unknown keys may request an early refresh with a ten-second throttle; provider revision remains part of the cache identity. Inspection found no material regression in these changes. This TTL does not imply a background timer: the first request after expiry refreshes the entry.

Location: `internal/app/upstream_jwt.go:292-295` through the network fetch and response parsing in `upstreamSigningKeys`.

The application-wide cache mutex stays locked across a potentially five-second JWKS request. Cached-key validation for every other provider must acquire the same mutex. A slow or unavailable JWKS endpoint for one configured provider therefore delays unrelated sign-ins and valid upstream logout requests. Requests with plausible unsigned claims and an unknown `kid` can initiate that network path before signature verification; provider-local fetch throttling does not isolate other providers from the resulting stalls.

Fix: keep the map mutex only for cache reads/updates and coordinate refreshes per provider/cache identity. Perform network I/O outside the global lock; cached keys for another provider must remain immediately usable. Verify with two providers, a blocked JWKS response for A, and a cached valid logout for B completing without waiting for A.

## Reviewed safeguards

Provider-row locking surrounds callback consumption, binding, final session issuance, logout, and provider edits. The session-binding read before that lock is followed by provider validation and a locked login-row existence check, so logout/edit deletion cannot recreate a deleted login. Logout watermarks cover callbacks that have not yet acquired a binding, and their minimum retention exceeds the ten-minute login lifetime. Provider edits revoke both derived sessions and pending provider login rows, and downstream revocation uses the existing session-delete path. Admin forms clear the client secret before rendering; provider audits contain IDs rather than configuration or credentials.

Both original findings are resolved by the inspected changes. No additional critical or important source-level defect was confirmed in this scoped re-review. Full PostgreSQL and race-suite verification remains owned by the implementing agent; this report is not an independent rerun of those suites.
