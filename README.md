# Guard

Guard provides OpenID Connect and private ForwardAuth for your applications,
with password/upstream login, MFA and an administrator dashboard.
It runs as one Go binary backed by PostgreSQL.

Requires Go 1.26 or later and PostgreSQL 14 or later. Direct runtime dependencies
are pgx/v5 and go-webauthn; sqlc generates the checked-in database code. HTTP,
templates, upstream OAuth, provider OAuth/JWT, passwords, TOTP, encryption,
logging, migrations, and background work use the Go standard library.
WebAuthn and pgx bring their own indirect dependencies.

## Run locally

From the repository root, with a PostgreSQL database you own:

```sh
export DOMAIN=http://localhost:4444
export DATABASE_URL='postgres://guard:password@localhost:5432/guard?sslmode=disable'
export MFA_ENCRYPTION_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
go run ./cmd/guard
```

Save `MFA_ENCRYPTION_KEY` securely and keep it through restarts. Startup applies
embedded SQL migrations and prints a random password for the initial `system`
administrator once. Treat those logs as sensitive. Create your own administrator
and enroll MFA at `/security`. The initial `system` account can then be disabled
from `/admin/users/0`; its password, role, authenticators, and sessions can be
managed there like other accounts.

The public service listens on port 4444; the separate private ForwardAuth service
listens on `127.0.0.1:4445` by default. Use HTTPS outside loopback development.
No environment file is loaded by the binary; export settings or use Compose.

Deleting a group automatically disables any client that loses its last access
rule. Disabled clients reject authentication and token use and are hidden from
the launcher. Review their access rules before clearing **Disable this client**
in the client settings to restore access.

## Docker Compose

```sh
cp guard.env.example guard.env
cp .env.example .env
# Edit DOMAIN and MFA_ENCRYPTION_KEY in guard.env.
# Keep or change GUARD_IMAGE to select the published image.
chmod 600 guard.env .env
docker compose pull
docker compose up -d
docker compose logs guard
```

To build the current checkout instead of using a published image, run
`docker compose up --build -d`. For a standalone image, run
`docker build -t guard:local .`.

Compose creates a persistent PostgreSQL volume and uses passwordless trust
authentication on a private, internal Docker network shared only by Guard and
PostgreSQL. The database port is not published. Trust authentication is configured
through `POSTGRES_HOST_AUTH_METHOD=trust` when PostgreSQL initializes its volume.
Both Guard ports are published on loopback. Point an HTTPS reverse proxy at
4444 and keep 4445 accessible only to the proxy. On a shared Docker network,
use `guard:4444` and `guard:4445`. Configure `AUDIT_TRUSTED_PROXIES` for the
actual proxy peers and overwrite client-supplied forwarded headers.

Back up PostgreSQL with `pg_dump` and keep the MFA key/configuration with the
backup. Restoring an old binary after a schema change requires a matching
database backup. Guard retains audit/access logs; monitor storage growth.

The former Rust/SQLite data is not imported. Start with an empty PostgreSQL
database; keep any old SQLite backup separately. Existing Go PostgreSQL data
and the MFA encryption key continue to work through this repository layout change.

## Settings

| Variable | Default / purpose |
| --- | --- |
| `DOMAIN` | Required public origin, HTTPS except loopback |
| `DATABASE_URL` | Required PostgreSQL URL; use TLS for remote databases |
| `LISTEN_ADDR` | `0.0.0.0:4444` |
| `FORWARDAUTH_LISTEN_ADDR` | `127.0.0.1:4445` |
| `MFA_ENCRYPTION_KEY` | 32 random bytes encoded as unpadded base64url; required for TOTP |
| `PASSWORD_DISABLED` | `false` |
| `BRAND_NAME` | `Guard`; header, page titles, security key display name, and new authenticator enrollments |
| `BRAND_ICON_FILE` | Optional local PNG, JPEG, GIF, SVG, ICO, or WebP file; header icon and favicon |
| `AUDIT_TRUSTED_PROXIES` | Comma-separated IP addresses/CIDRs; none trusted by default |
| `ACCESS_LOG_EXPORT_URL` | Optional HTTPS collector endpoint |
| `ACCESS_LOG_EXPORT_TOKEN` | Optional collector bearer credential |
| `AUDIT_EVENT_REPORTS_PER_MINUTE` | `600` per client |

Sessions last 18 hours. Password login permits five attempts per IP, then one
additional attempt per minute. Passwords use salted PBKDF2-HMAC-SHA256 with
600,000 iterations. There is no bcrypt import or `PASSWORD_BCRYPT_COST` setting.

To use custom branding, set these values in `guard.env`:

```dotenv
BRAND_NAME=Company Login
BRAND_ICON_FILE=/branding/icon.svg
```

Mount the icon into the `guard` service in `compose.yaml`:

```yaml
services:
  guard:
    volumes:
      - ./branding/icon.svg:/branding/icon.svg:ro
```

The container runs as UID/GID 65532; make the icon readable by that user.
Restart Guard after changing branding settings. The configured file must exist
and be readable at startup. Guard serves it publicly at `/branding/icon`.
Existing authenticator entries retain the name they were enrolled with.

## Upstream login

Configure upstream providers under **Administration > Login providers**
(`/admin/providers`). Upstream OIDC environment variables have been removed;
there is no automatic import. Provider changes apply immediately without a
restart. Password login and the initial administrator remain available according
to `PASSWORD_DISABLED`; keep password login enabled until upstream access works.

Add a display name, client ID and client secret. Guard generates a unique,
permanent slug from the name. Duplicate names receive a numeric suffix; renaming
a provider keeps its existing slug. Choose one setup mode:

- **OIDC discovery:** enter the full **OIDC configuration URL**, including the
  JSON document path (usually `/.well-known/openid-configuration`). Guard reads
  the issuer, authorization, token, user info and JWKS URLs from that document.
- **Manual OIDC:** enter the exact issuer identifier, authorization URL, token
  URL, user info URL and JWKS URL yourself. No discovery request is made.
- **OAuth2:** enter the authorization, token and user info URLs yourself. This
  mode does not require discovery, an ID token, an issuer or a JWKS endpoint.
  Configure the profile's subject, email and email-verification field paths,
  such as `account.id`, `emails.0.address` and `emails.0.verified`. Subjects may
  be strings or numbers. Email verification must be a JSON boolean `true`.

Use HTTPS, or HTTP on loopback for development. Token endpoint credentials are
always sent in the Authorization header using HTTP Basic authentication. Choose the
provider's required scopes and enable PKCE when supported. OIDC requires
`openid`. Signing algorithms are selected automatically from supported algorithms
advertised by discovery, or from supported algorithms compatible with the JWKS
for manual setup. Guard supports
RSA/RSASSA-PSS, P-256/P-384/P-521 ECDSA and Ed25519 signatures. All modes require
a profile endpoint that returns a stable subject and a verified email address.

Register the callback URL shown on the provider page, for example
`https://auth.example.com/login/work/callback`. The slug stays fixed so callback
URLs do not change. Client secrets are stored in PostgreSQL and never shown in
the UI or audit data. Leave the secret field blank when editing to keep it.
Protect database access and backups as credential-bearing material.

For OIDC, Guard verifies the upstream ID token's signature, exact issuer, client audience,
nonce and expiry; userinfo `sub` must match the signed subject. A verified email
must match exactly one active local account. That account/email match is retained
through MFA and rechecked before creating a Guard session. Accounts are created
locally, not automatically provisioned. Saving provider changes, disabling it, or
deleting it revokes its Guard sessions and pending logins. Existing endpoint
settings remain editable if the provider is offline; use Refresh discovery to
reload metadata explicitly.

For OIDC providers, enable **Accept logout requests from this provider** and register the shown endpoint at the
upstream provider, for example
`https://auth.example.com/login/work/backchannel-logout`. Guard accepts signed
form-encoded `logout_token` requests without browser cookies. It verifies issuer,
audience, algorithm/signature, `iat`/`exp`, `jti`, logout event and `sub`/`sid`,
rejects nonce and ID-token substitution, and handles retries idempotently. Logout
tokens must be issued within five minutes (up to 60 seconds of future clock skew).
Matching provider-derived sessions and pending MFA logins are revoked; password
sessions and other providers' sessions remain active. Existing downstream
back-channel logout notifications are queued in the same database transaction.
Logout watermarks prevent delayed callbacks from restoring an ended session.

JWKS are cached independently per provider for **24 hours**. An unknown `kid`
can trigger an earlier refresh, throttled to once per ten seconds; provider
configuration changes invalidate its cache. Slow key discovery at one provider
does not block the others. Keys are fetched only from the configured JWKS URI,
with bounded responses/timeouts and no redirects. A temporary key-fetch failure
returns HTTP 503 so the upstream can retry; an invalid logout request returns HTTP 400.

## Applications and administration

Use `/admin` for users, sessions, groups, clients, security logs and access logs.
Password/role changes and disabling/deleting users revoke sessions and pending
MFA. MFA management requires a recent login. TOTP secrets are encrypted with
AES-GCM and bound to their owner; accepted time steps cannot be replayed.
Recovery codes are single-use. Security keys use go-webauthn with expiring,
browser/session-bound ceremonies. TOTP setup provides a manual secret and
`otpauth://` link, rather than a generated QR image.

Create an OpenID Connect client and register its exact callback URLs. Discovery:

```text
https://auth.example.com/oauth2/CLIENT_SLUG/.well-known/openid-configuration
```

Supports authorization code, plain/S256 PKCE, RS256 ID tokens, rotating refresh
tokens, userinfo and revocation. Replaying an authorization code or refresh token
revokes the corresponding token family. Client rules apply to every grant and
session check. Clients without rules allow all active signed-in users. Lower
priority rules win; deny wins ties; unmatched users are denied when rules exist.

OIDC subjects (`sub`) are opaque, stable per-client identifiers derived using
HMAC-SHA256 with the user ID as the key and OAuth client ID as the message. They
survive restarts, username changes, client secret rotation, and signing key
rotation. Upgrading from numeric subjects changes existing account identities:
reassociate accounts in downstream applications before relying on existing links.
The `profile` scope includes the stored username as `username`,
`preferred_username`, and `name`.

Downstream OIDC apps can request `openid`, `profile`, `email`, and `groups`.
The `groups` scope adds a `groups` array of active group names to ID tokens and
UserInfo, sorted by name. No memberships produces `[]`; omitting the scope omits
the claim. UserInfo reflects current memberships, and refreshed ID tokens use
current memberships as well. Guard administrator permission is not exposed as
an app role or group.

The dashboard also includes a **UserInfo simulator**. Select an accessible OIDC
client and scopes to see your current UserInfo JSON, including that client’s
`sub`, using the same claims as the UserInfo endpoint.

The home page includes an **App launcher** listing clients the signed-in user can
access under the existing group rules. Each app opens the origin of its first
registered redirect URI (or its first registered ForwardAuth origin). Callback
paths and query strings are excluded. Apps without a registered URI appear
without a launch link. The list updates when group access or membership changes.

For ForwardAuth, register each allowed origin (for example
`https://app.example.com`, without a path). The proxy must supply exactly one
`X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` to the private
listener, forward the browser's Cookie header, and propagate Set-Cookie and
Location back to the browser. On success trust `X-Guard-User-Id` and
`X-Guard-Username`; strip incoming copies of these identity headers.

To recover the client IP, set `AUDIT_TRUSTED_PROXIES` to the IP addresses or
CIDRs of the proxies connecting to Guard. Guard walks all `X-Forwarded-For`
header values from right to left and stops at the first untrusted address.
If that header is absent, it accepts a single `X-Real-IP` from a trusted peer.
Configure the proxy to overwrite `X-Real-IP` and overwrite or safely append to
`X-Forwarded-For`. Forwarded IP headers from untrusted peers are ignored.
With Docker port publishing, the peer may be the Docker gateway rather than
`127.0.0.1`; configure the address Guard actually receives. The recovered IP
is used for login rate limits, login audit events, and OAuth2/ForwardAuth
access records.

Guard sends the browser through `/oauth2/authorize` and back to `/.guard/login`
on the application origin. Route that callback through ForwardAuth too. Each
flow is browser-bound, short-lived, and single-use. HTTPS application cookies
use the `__Host-` prefix. For Nginx `auth_request`, call `/auth_request` and adapt
a 401 with Location to an external 303, retaining the first Set-Cookie header.
The callback itself also needs that adapter when sent as an auth subrequest.
Caddy/Traefik redirect-capable checks may call `/` and propagate 303 directly.

## Journals and application reports

Detailed request records and application reports are opt-in per client. The
admin access log supports client, Guard session and source filters (`request`,
`application`, `configuration`). Sensitive URL queries and credential fields
are not recorded. Collector delivery uses an outbox, stable event IDs, bounded
batches, and retries; collectors must deduplicate by `event_id`.

Applications report events using HTTP Basic client authentication and a live
application session/access token in the JSON body:

```http
POST /oauth2/event
Authorization: Basic BASE64_CLIENT_ID_COLON_SECRET
Content-Type: application/json

{"session_token":"APPLICATION_TOKEN","report_id":"d54e3d5d-cf3c-4187-888a-4fa62db90ef5","event":"file.saved","outcome":"success","resource":"/files/42","metadata":{"size":1234}}
```

The body is limited to 8 KiB. Outcomes: `success`, `failure`, `denied`, `started`,
`completed`. Optional `occurred_at` is RFC3339, bounded by the session and five
minutes into the future. Metadata permits up to 24 scalar fields with bounded,
nonsecret names/values. Identity and secret field names are rejected; URLs lose
queries/fragments. A new report returns 202, an identical retry 200, a reused ID
with changed content/session 409, and an exceeded per-client limit 429.

## Development and verification

```sh
sqlc generate       # sqlc 1.31.1; generated files are committed
sqlc vet
go test ./...
go vet ./...
go build ./cmd/guard

# Use a dedicated test database: tests create/drop isolated schemas.
export GUARD_TEST_DATABASE_URL='postgres://guard:password@localhost:5432/guard_test?sslmode=disable'
go test -race ./...
```

Without `GUARD_TEST_DATABASE_URL`, integration tests skip explicitly. Tests cover
password sessions, administration, OAuth signing/grants/concurrent replay,
TOTP/recovery replay, ceremony binding, ForwardAuth completion, application
report deduplication/rate limits and collector retries. A software authenticator also verifies enrollment and signed WebAuthn login end to end. Physical security-key interoperability requires a browser and authenticator.

`internal/ids` defines distinct integer types for all entity identities. sqlc's
per-column overrides propagate those types to primary keys, foreign keys and
query parameters, including nullable IDs. SQL lives in `sql/queries`, embedded
migrations in `internal/db/migrations`. The module is
`github.com/le0developer/guard`.

CI in `.github/workflows/image.yml` checks formatting, sqlc regeneration, vet,
PostgreSQL race tests and builds on Go 1.26 and 1.27. Container builds for
`linux/amd64` and `linux/arm64` run after these checks. Pull requests build images
without publishing. The default branch publishes `latest`; published builds also
receive a commit tag, and `v*` release tags produce version tags. Images publish
to `ghcr.io/le0developer/guard`. The Docker build cross-compiles Go on the native
builder without QEMU and packages a static binary in a nonroot runtime image.

## Backend session checks and logout

Applications with their own session cookies can check Guard on the server with
`POST /oauth2/introspect`. Authenticate using HTTP Basic with the client ID and
secret (`client_secret_basic`), or form fields `client_id` and `client_secret`
(`client_secret_post`), and send a form-encoded `token` containing an access or
refresh token. Tokens are scoped to their issuing client. Unknown, expired,
revoked, or inaccessible tokens return `{"active":false}`; Guard also checks the
underlying session, account state, and current access rules. A storage failure
returns HTTP 503, which must not be treated as a successful validation.

For example, check at session creation and cache a positive result for at most
30 seconds, bounded by the returned `exp`. Check again after the cache expires
and end the application's session when `active` is false. Choose the interval
according to the acceptable revocation delay; a successful check is only a
snapshot. Keep the client secret and these requests on the backend. Guard does
not implement iframe session monitoring.

To receive logout notifications, edit an OpenID Connect client under
`/admin/clients` and set its optional **Logout URI** and **Require session
identifier (sid)** checkbox. Use an absolute HTTPS endpoint without credentials,
fragments, wildcards, whitespace, backslashes or control characters (maximum
2048 bytes). Explicit ports must be between 1 and 65535. HTTP is allowed
only for localhost or loopback development. Switching to Forward auth clears
these settings; secret rotation preserves them. Client discovery advertises
`introspection_endpoint`, supported introspection authentication methods,
`backchannel_logout_supported`, and `backchannel_logout_session_supported`.

Guard sends a form-encoded `logout_token` to the configured endpoint. This is an
RS256-signed JWT with `typ: logout+jwt` and claims `iss`, `aud`, `iat`, `exp`,
`jti`, `sub`, `sid`, and
`events: {"http://schemas.openid.net/event/backchannel-logout": {}}`; it contains
no `nonce`. The application must verify the signature using its issuer's JWKS,
allow only the expected algorithm and token type, check issuer, audience, time
bounds and logout event, reject any nonce, and prevent replay using `jti` until
the token expires. Match `sid` against the `sid` received in the ID token for
that application's session, and terminate that session in the application's
own store. Guard always includes `sid`, including when session-required is set.
Treat repeat delivery of the same logout event idempotently.

Notifications are durable and delivered at least once when a Guard session ends
through logout, administrator or MFA revocation, or expiry. Return HTTP 200 or
204 after processing. Network failures, HTTP 408, 429 and 5xx responses are retried
with backoff for up to 24 hours. Other 4xx responses stop delivery; redirects are
never followed. Changing or removing the configured endpoint cancels pending
deliveries for the former endpoint. Keep introspection checks where a bounded
revocation delay matters: callbacks can fail or exhaust the retry window.

Existing application sessions enter this tracking when Guard issues or refreshes
an ID token containing `sid`; sign in again after upgrading if needed. A worker
crash releases its claim after 30 seconds. In-flight deliveries may already have
started when endpoint settings change.

## Outbound SCIM provisioning

For a saved OIDC client, open **Administration > Clients > Configure SCIM
provisioning**. Enter the target service's SCIM 2.0 base URL and bearer secret,
then enable provisioning. Copy the endpoint and secret from the target service's
provisioning settings.

Guard provisions active users permitted by that client's group access rules.
Without rules, this includes all active users with an email address. Users without
an email are skipped and excluded from synchronized group membership. Non-empty
email addresses must still be valid and unique. Map `userName` and
primary `emails` to email, `displayName` to the Guard username, and `externalId`
to a stable per-client identity. All active Guard groups are synchronized,
including empty groups; membership includes only assigned users. Accounts are
never adopted solely by matching email. Existing target accounts without the
matching Guard `externalId` can produce a conflict requiring reconciliation by
an operator.

Changes are queued transactionally and delivered in the background. Disabled,
deleted, or newly denied users previously managed by Guard receive `active:false`
and leave synchronized groups; restored access sends `active:true`. Deleted
managed groups are removed. Disabling provisioning or deleting/converting its
client stops further delivery and leaves remote accounts unchanged. Changing the
endpoint requires entering a secret and starts a new mapping generation; Guard
leaves the old endpoint unchanged. A request already sent cannot be recalled.

The admin page shows synchronization status, sanitized failures, the last
successful sync, and **Sync now**. Network failures, HTTP 408/429 and server errors
retry with exponential backoff (five seconds to five minutes; `Retry-After` can
extend this up to one hour). Authentication, identity conflicts and unsupported
protocol operations require attention; saving configuration, changing the
directory or choosing Sync now retries them. Enabled clients also reconcile every
15 minutes to repair remote drift. Pending progress survives restarts.

Supported SCIM subset: core Users and Groups, bearer authentication, paginated
`externalId` equality lookup, resource GET/POST, PATCH updates, and managed group
DELETE. If discovery explicitly reports PATCH unsupported, or PATCH returns
405/501, Guard uses PUT while preserving unrelated returned attributes. The
client does not provision passwords, use Bulk, synchronize inbound changes, or
provide custom attribute mapping. Endpoints require HTTPS, except HTTP loopback
for development; redirects are rejected. Resource request/response bodies are
limited to 2 MiB and lookups to 100,000 results / 1,000 pages. Secrets are encrypted
with `MFA_ENCRYPTION_KEY`, bound to their client, and never shown again. Include
that key in secure backups. Renaming users or rotating credentials preserves
remote mappings.

Live compatibility must be verified against your configured service; automated
tests use a local SCIM service.
