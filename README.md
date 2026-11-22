# Guard

Guard provides OpenID Connect and ForwardAuth for your applications. It has
local password login, upstream OIDC login, user and group management, TOTP,
security keys, backup codes, and an administrator dashboard.

## Deploy with Docker Compose

Run Guard behind an HTTPS reverse proxy. Use one Guard instance with a
persistent data volume.

The runtime image has no shell or package manager. Use `docker compose logs
guard` to read its output.

Images publish to `ghcr.io/le0developer/guard`.

```sh
export GUARD_IMAGE=ghcr.io/le0developer/guard:latest
```

Set `GUARD_IMAGE` in each shell where you run Compose, or save it in a `.env`
file next to `compose.yaml`.

Generate a key for authenticator apps. Keep this key through upgrades and
include it in your backups.

```sh
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Create `guard.env` next to the supplied `compose.yaml`. Set your public URL and
paste the generated key.

```dotenv
DOMAIN=https://auth.example.com
MFA_ENCRYPTION_KEY=PASTE_GENERATED_KEY_HERE
```

Protect the file, then start Guard.

```sh
chmod 600 guard.env
docker compose up -d
docker compose logs guard
```

On the first start, Guard prints a generated password for the `system`
administrator. Sign in at your public URL, create your administrator account,
and enroll MFA. Treat the startup logs as sensitive because they contain that
initial password.

The Compose file publishes both ports on the host's loopback address:

| Host address     | Purpose                        |
| ---------------- | ------------------------------ |
| `127.0.0.1:4444` | Login, administration and OIDC |
| `127.0.0.1:4445` | Private ForwardAuth service    |

Point your HTTPS reverse proxy at port 4444 for `auth.example.com`. Keep port
4445 private. ForwardAuth trusts the proxy headers it receives. See the
[Caddy, Traefik and Nginx examples](docs/forwardauth.md) for protected
applications.

If your reverse proxy runs in Docker, connect it to Guard's Compose network and
use `guard:4444` and `guard:4445`. The loopback mappings above are for proxies
running on the host.

Set `AUDIT_TRUSTED_PROXIES` in `guard.env` to the IP addresses or CIDRs of the
proxies connecting to Guard. Guard uses these addresses to decide whether to
trust forwarded client IPs for login limits and access records. Configure the
proxy to overwrite client-supplied forwarded headers. With Docker port mappings,
the connecting address may be the Docker gateway rather than `127.0.0.1`.

Guard stores its database in the `guard-data` volume. Keep that volume when
replacing the container. For a bind mount, give UID 10001 write access to the
directory.

## Configuration

Pass settings through the container environment. Docker Compose loads
`guard.env` in the supplied setup.

| Setting                          | Required        | Value                                                                                                                                            |
| -------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `DOMAIN`                         | **Yes**         | Public base URL, such as `https://auth.example.com`. Use HTTPS outside local development.                                                        |
| `DATABASE_URL`                   | No              | The image defaults to `sqlite:///data/guard.sqlite3`. Keep the database on persistent storage.                                                   |
| `LISTEN_ADDR`                    | No              | The image listens on `0.0.0.0:4444` for the public server.                                                                                       |
| `FORWARDAUTH_LISTEN_ADDR`        | No              | The image listens on `0.0.0.0:4445` for the private ForwardAuth service. Restrict access to your proxies.                                        |
| `MFA_ENCRYPTION_KEY`             | **Recommended** | Required for authenticator apps. Generate a 32-byte base64url key with the command above. Losing it makes existing TOTP authenticators unusable. |
| `PASSWORD_DISABLED`              | No              | Set to `true` to disable password login after you have confirmed upstream login works. Defaults to `false`.                                      |
| `AUDIT_TRUSTED_PROXIES`          | No              | Comma-separated proxy IPs or CIDRs. Forwarded client IPs on the public server are ignored unless the connecting proxy is trusted.                |
| `ACCESS_LOG_EXPORT_URL`          | No              | Optional HTTPS destination for the access journal.                                                                                               |
| `ACCESS_LOG_EXPORT_TOKEN`        | No              | Optional bearer credential for that destination. Give it append-only access at the collector.                                                    |
| `AUDIT_EVENT_REPORTS_PER_MINUTE` | No              | Application event limit per client. Defaults to `600`.                                                                                           |

Guard sessions last 18 hours. Password login allows five attempts per IP
initially, then one more per minute. A container restart resets that login
limit.

## Upstream OIDC login

Add one group of settings per provider to `guard.env`, then restart Guard.
Use `OIDC_<NAME>_` as the prefix, with uppercase letters, digits and
underscores in the name.

```dotenv
OIDC_PERSONAL_AUTHORIZE_URL=https://personal.example.com/authorize
OIDC_PERSONAL_TOKEN_URL=https://personal.example.com/token
OIDC_PERSONAL_USERINFO_URL=https://personal.example.com/userinfo
OIDC_PERSONAL_CLIENT_ID=YOUR_PERSONAL_CLIENT_ID
OIDC_PERSONAL_CLIENT_SECRET=YOUR_PERSONAL_CLIENT_SECRET
OIDC_PERSONAL_SUPPORTS_PKCE=true

OIDC_WORK_AUTHORIZE_URL=https://provider.example.com/authorize
OIDC_WORK_TOKEN_URL=https://provider.example.com/token
OIDC_WORK_USERINFO_URL=https://provider.example.com/userinfo
OIDC_WORK_CLIENT_ID=YOUR_WORK_CLIENT_ID
OIDC_WORK_CLIENT_SECRET=YOUR_WORK_CLIENT_SECRET
OIDC_WORK_SCOPES=openid profile email
OIDC_WORK_SUPPORTS_PKCE=true
```

Guard lists both providers on the login page. Register these callback URLs
with their respective providers:

- Personal: `https://auth.example.com/login/personal/callback`
- Work: `https://auth.example.com/login/work/callback`

The name in the callback path is the lowercase environment name. Underscores
stay unchanged. The names `FORM` and `MFA` are reserved.

Each provider requires its authorize, token and userinfo URLs, client ID,
and client secret. Scopes default to `openid profile email`. PKCE defaults
to `false`; enable it if the provider supports it. Guard reports missing
or invalid provider settings at startup.

The previous single-provider settings still work. Keep
`OIDC_PROVIDER_NAME` and the unprefixed settings such as `OIDC_CLIENT_ID`
together. That provider's name must differ from any named provider.

Create the local Guard accounts before signing in through a provider and
set their email addresses in the user editor. Guard matches the provider's
verified `email` claim to the account's email address, ignoring ASCII letter
case. The provider must return `email_verified=true`; missing or unverified
addresses cannot sign in. Include `email` in the requested scopes.

Exactly one active account must match the address. Guard rejects ambiguous
matches. Multiple providers can sign in to the same account when they verify
the same email address. Usernames do not need a provider prefix or an
upstream subject ID. This applies to both named providers and the legacy
single-provider configuration.

Keep password login enabled until you have verified access to an
administrator account through a provider.

## Administration and applications

Open `/admin` to manage users, sessions, groups and clients. Disabling an
account or resetting its password revokes its sessions. Administrators can also
manage a user's MFA methods and backup codes.

For OIDC applications, create an OpenID Connect client, register its exact
callback URL, and copy the client ID, secret and discovery URL from its page.
Each client has its own discovery URL:

```text
https://auth.example.com/oauth2/CLIENT_SLUG/.well-known/openid-configuration
```

Use that discovery URL in the application. Guard supports authorization-code
login with PKCE and refresh tokens. Available scopes are `openid`, `profile` and
`email`.

For ForwardAuth applications, create a Forward auth client, register its allowed
origins, and follow the [proxy setup guide](docs/forwardauth.md).

Clients without access rules allow every signed-in user. Add group rules to
restrict access. Lower priority numbers take precedence, and deny rules win
ties. Once a client has rules, users who match none of them cannot access it.

Users can enroll authenticator apps, security keys and backup codes under **My
account > Manage security**. Security keys require HTTPS, except for local
development on `http://localhost`. Save backup codes before leaving the page.

## Logs and backups

Administrators can view security events at `/admin/audit`. Each client can also
enable detailed access records and session-bound application reports. View those
records at `/admin/access-log`. See the
[access journal guide](docs/access-journal.md) for collector configuration and
the application event API.

Guard removes expired authentication records in the background. It retains audit
records and access journals, so allow disk space for them and monitor collector
delivery if you enable export.

Back up the data volume and `guard.env` together. Stop Guard before copying its
database directory.

```sh
docker compose stop guard
docker compose cp guard:/data ./guard-backup
docker compose start guard
```

Keep the backup private. It contains account data, credentials and
authentication records. Save the MFA key with it. To restore, stop Guard and
restore the data directory and environment file before starting it again.

## Updates

Back up Guard before upgrading. Startup applies database upgrades. If you need
to roll back after a database upgrade, restore the matching database backup too.

```sh
docker compose pull
docker compose up -d
```

The image workflow publishes `latest` from the repository's default branch and
`sha-<commit>` for each published build. A tag such as `v1.2.3` publishes image
tags `1.2.3` and `1.2`. Pin a version or image digest when you want to control
upgrades. Pull requests build the image without publishing it.

To build an image locally:

```sh
docker build -t guard:local .
export GUARD_IMAGE=guard:local
docker compose up -d
```
