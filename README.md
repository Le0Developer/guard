# Guard

## Docker Compose

Install Docker with the Compose plugin, then run from the repository root:

```sh
cp guard.env.example guard.env
chmod 600 guard.env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Edit `guard.env`:

- Set `DOMAIN` to Guard's public HTTPS origin, such as `https://auth.example.com`.
- Set `MFA_ENCRYPTION_KEY` to the generated key. Keep this key through restarts
  and include it in database backups.
- Set `AUDIT_TRUSTED_PROXIES` to the addresses or CIDRs of the proxies connecting
  to Guard.

Start Guard and read the initial administrator password:

```sh
docker compose pull
docker compose up -d
docker compose logs guard
```

Compose includes PostgreSQL and a persistent database volume. Both Guard ports
are published on loopback. Configure an HTTPS reverse proxy to send public
requests to `127.0.0.1:4444`. Keep port `4445` accessible only to the proxy.
For a proxy on the shared Docker network, use `guard:4444` and `guard:4445`.

To select an image, set `GUARD_IMAGE` in your shell or a Compose `.env` file.
The default is `ghcr.io/le0developer/guard:latest`. To build this checkout, use
`docker compose up --build -d`.

## Run locally

Install Go 1.26 or later and PostgreSQL 14 or later. Create a database owned by
the PostgreSQL user you will use for Guard, then run from the repository root:

```sh
export DOMAIN=http://localhost:4444
export DATABASE_URL='postgres://guard:password@localhost:5432/guard?sslmode=disable'
export MFA_ENCRYPTION_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
go run ./cmd/guard
```

Save the generated key before restarting. Use HTTPS outside loopback development
and enable TLS in `DATABASE_URL` for a remote database. Guard applies database
migrations at startup. The binary reads exported environment variables; it does
not load `guard.env` itself.

## Initial administrator

Open `DOMAIN` in your browser and sign in as `system` with the password from the
startup logs. You must choose a new password on first login. Create your own
administrator under `/admin/users` and enroll MFA
at `/security`. Sign in with the new administrator, then disable the initial
`system` account at `/admin/users/0`.

Administrators can enable **Force password reset on next login** when creating or
editing a user, or when resetting their password. The requirement applies after
MFA for both password and external provider sign-ins, including accounts without
a local password. Users must set a new local password before accessing Guard or
connected applications. Enabling the flag revokes existing sessions. Existing
accounts are not flagged automatically during upgrades.

## Settings

Set these variables in `guard.env` for Compose or export them when running the
binary directly. Restart Guard after changing them.

| Variable | Default / purpose |
| --- | --- |
| `DOMAIN` | Required public origin; HTTPS except on loopback |
| `DATABASE_URL` | Required PostgreSQL URL; Compose supplies this |
| `LISTEN_ADDR` | `0.0.0.0:4444` |
| `FORWARDAUTH_LISTEN_ADDR` | `127.0.0.1:4445`; Compose uses `0.0.0.0:4445` inside the container |
| `MFA_ENCRYPTION_KEY` | 32 random bytes encoded as unpadded base64url; required for TOTP and SCIM credentials |
| `PASSWORD_DISABLED` | `false`; keep password login enabled until upstream login works |
| `BRAND_NAME` | `Guard` |
| `BRAND_ICON_FILE` | Optional local PNG, JPEG, GIF, SVG, ICO, or WebP file |
| `AUDIT_TRUSTED_PROXIES` | Comma-separated proxy IP addresses/CIDRs; none trusted by default |
| `ACCESS_LOG_EXPORT_URL` | Optional HTTPS collector endpoint |
| `ACCESS_LOG_EXPORT_TOKEN` | Optional collector bearer credential |
| `AUDIT_EVENT_REPORTS_PER_MINUTE` | `600` per client |

### Branding

Set the name and icon path in `guard.env`:

```dotenv
BRAND_NAME=Company Login
BRAND_ICON_FILE=/branding/icon.svg
```

Mount the icon into the Guard container in `compose.yaml`:

```yaml
services:
  guard:
    volumes:
      - ./branding/icon.svg:/branding/icon.svg:ro
```

Make the file readable by UID/GID `65532:65532` and restart Guard.

### Reverse proxy

Set `AUDIT_TRUSTED_PROXIES` to the proxy peer addresses Guard actually receives.
With Docker port publishing, this may be the Docker gateway address.
Configure the proxy to overwrite `X-Real-IP` and overwrite or safely append to
`X-Forwarded-For`.

## Upstream login

Create local user accounts under `/admin/users` with email addresses matching
their verified upstream addresses. Keep each email unique among active accounts.

Open **Administration > Login providers** at `/admin/providers`. Add the provider's
name, client ID and client secret, then choose a setup mode:

- **OIDC discovery:** enter the full OIDC configuration URL, usually ending in
  `/.well-known/openid-configuration`.
- **Manual OIDC:** enter the issuer, authorization, token, user info and JWKS URLs.
- **OAuth2:** enter the authorization, token and user info URLs. Set the profile
  field paths for the subject, email and email-verification flag, such as
  `account.id`, `emails.0.address` and `emails.0.verified`. The verification flag
  must be a JSON boolean `true`.

Use HTTPS, or HTTP on loopback for development. Configure the provider to accept
HTTP Basic client authentication at its token endpoint. Select the required
scopes, including `openid` for OIDC, and enable PKCE when supported.

Register the callback URL shown on the provider page with the upstream service,
for example `https://auth.example.com/login/work/callback`.

For upstream OIDC logout, enable **Accept logout requests from this provider**
and register the displayed logout endpoint with the provider, for example
`https://auth.example.com/login/work/backchannel-logout`.

Use an OIDC provider that supports `max_age` and signed `auth_time` when
applications require fresh authentication. OAuth2-only providers cannot satisfy
those requests.

Verify upstream login before setting `PASSWORD_DISABLED=true`.

## Connect applications

Create users and groups under `/admin`, then add application clients under
`/admin/clients`. Configure each client's group access rules. Add an Allow rule
to restrict access to selected groups; leaving the rule list empty permits all
active signed-in users.

### OpenID Connect

Create an OpenID Connect client and register its exact callback URLs. Copy its
client ID and secret into the application. Set the application's discovery URL:

```text
https://auth.example.com/oauth2/CLIENT_SLUG/.well-known/openid-configuration
```

Select the application's required scopes from `openid`, `profile`, `email` and
`groups`. Configure S256 PKCE when the application supports it.

If the application supports back-channel logout, enter its HTTPS **Logout URI**
in the client settings and set **Require session identifier (sid)** as required
by the application.

### ForwardAuth

Create a Forward auth client and register each application origin without a
path, such as `https://app.example.com`.

Configure the proxy to call Guard's private listener on port `4445` and:

- Supply one value each for `X-Forwarded-Proto`, `X-Forwarded-Host` and
  `X-Forwarded-Uri`.
- Forward the browser's `Cookie` header and return Guard's `Set-Cookie` and
  `Location` headers to the browser.
- Route `/.guard/login` on the application origin through ForwardAuth too.
- Strip incoming `X-Guard-User-Id` and `X-Guard-Username` headers, then use the
  values Guard returns after a successful check.

For Caddy or Traefik, call `/` and propagate redirects. For Nginx `auth_request`,
call `/auth_request` and convert a 401 with `Location` into an external 303,
retaining the first `Set-Cookie` header. Apply that adapter to the callback too.

### SAML 2.0

Create a SAML 2.0 client, save it, then open **Configure SAML service provider**.
Enter the exact SP entity ID and HTTP-POST ACS URLs, one per line as `index URL`,
and choose the default index. Register the displayed Guard metadata URL (also
its IdP entity ID) and SSO URL with your application. Use HTTPS except loopback.

Only SP-initiated HTTP-Redirect requests and HTTP-POST responses are supported.
Both response and assertion are RSA-SHA256 signed. Existing login providers, MFA
and client group rules apply. For first use of a persistent NameID, the SP must
send `NameIDPolicy AllowCreate="true"`. Email NameID requires a valid email
belonging to exactly one active account; changing it can change the application's
account association. Guard sends `uid`, `username`, `email` and the user's active
`groups` using fixed attribute names. Empty optional values are omitted.

To require signed requests, enable that option and paste the SP's RSA signing
certificate(s). Supplied signatures are always verified. ForceAuthn requires a
new login bound to that request; OAuth2-only providers cannot prove freshness.
IsPassive never prompts. AuthnInstant records completion of the original Guard
login, including local MFA, rather than claiming an upstream authentication time.
Unsupported authentication-context requirements return an error.

Assertions expire after two minutes, capped by Guard session expiry. Application
session deadlines are also bounded by the client lifetime; the SP must enforce
them. Guard logout, account disable and group changes block future SSO but cannot
terminate an existing application session: SAML Single Logout is not supported.
There are no unsolicited responses, encrypted assertions or upstream SAML login.
The optional application login URL lets the launcher start SSO through the SP.

Each SAML client automatically gets one signing certificate and an encrypted
private key when created. The certificate remains stable when settings change;
there are no rotation controls or certificate-expiry checks in Guard. New
certificates use the X.509 no-expiration date (year 9999). Back up the database
together with `MFA_ENCRYPTION_KEY`. Upgrades preserve existing certificates,
including their encoded validity dates; applications may enforce those dates
independently. Import the certificate or Guard metadata into
the application. Configuration changes invalidate pending requests. If delivery
fails after issuance, start a new request from the SP.

### SCIM provisioning

For a saved OIDC client, open **Configure SCIM provisioning**. Enter the target
service's SCIM 2.0 base URL and bearer secret, then enable provisioning. Use
HTTPS, or HTTP on loopback for development.

Configure the target service to map `userName` and primary `emails` to email,
`displayName` to the Guard username, and `externalId` to the Guard identity.
Give assigned users valid, unique email addresses and configure the client's
group access rules before enabling synchronization. Use **Sync now** to check
the connection and review its status.

Set **Group whitelist** to one exact group name or pattern per line, such as
`Admins` and `team-*`. Matching is case-sensitive; `*` matches any characters,
including `/`. Blank syncs no groups; `*` alone syncs all groups. Existing SCIM
configurations retain `*` on upgrade. Groups previously managed by Guard are
deleted remotely when they stop matching. User assignment still follows the
client's access rules, independently of this group whitelist.
