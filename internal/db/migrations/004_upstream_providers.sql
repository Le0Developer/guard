CREATE TABLE upstream_providers (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 slug text NOT NULL UNIQUE,
 name text NOT NULL,
 issuer text NOT NULL,
 authorize_url text NOT NULL,
 token_url text NOT NULL,
 userinfo_url text NOT NULL,
 jwks_url text NOT NULL,
 client_id text NOT NULL,
 client_secret text NOT NULL,
 scopes text NOT NULL DEFAULT 'openid profile email',
 pkce boolean NOT NULL DEFAULT true,
 signing_alg text NOT NULL DEFAULT 'RS256',
 enabled boolean NOT NULL DEFAULT true,
 backchannel_logout_enabled boolean NOT NULL DEFAULT true,
 revision bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 deleted_at timestamptz
);
CREATE TABLE upstream_pending_logins (
 login_session_id bigint PRIMARY KEY REFERENCES login_sessions(id) ON DELETE CASCADE,
 provider_id bigint NOT NULL REFERENCES upstream_providers(id),
 user_id bigint NOT NULL REFERENCES users(id),
 matched_email text NOT NULL,
 subject text NOT NULL,
 sid text NOT NULL DEFAULT '',
 provider_revision bigint NOT NULL,
 token_issued_at bigint NOT NULL
);
CREATE TABLE upstream_sessions (
 session_id bigint PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
 provider_id bigint NOT NULL REFERENCES upstream_providers(id),
 subject text NOT NULL,
 sid text NOT NULL DEFAULT '',
 provider_revision bigint NOT NULL,
 token_issued_at bigint NOT NULL
);
CREATE INDEX ON upstream_sessions (provider_id, sid);
CREATE INDEX ON upstream_sessions (provider_id, subject);
CREATE INDEX ON upstream_pending_logins (provider_id);
CREATE TABLE upstream_logout_events (
 provider_id bigint NOT NULL REFERENCES upstream_providers(id),
 provider_revision bigint NOT NULL,
 jti text NOT NULL,
 subject text NOT NULL DEFAULT '',
 sid text NOT NULL DEFAULT '',
 issued_at bigint NOT NULL,
 expires_at timestamptz NOT NULL,
 retain_until timestamptz NOT NULL,
 PRIMARY KEY (provider_id,provider_revision,jti)
);
CREATE INDEX ON upstream_logout_events (provider_id,provider_revision);
CREATE INDEX ON upstream_logout_events (retain_until);
