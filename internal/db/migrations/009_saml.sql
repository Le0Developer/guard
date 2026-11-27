ALTER TABLE clients DROP CONSTRAINT clients_client_type_check;
ALTER TABLE clients ADD CHECK (client_type IN ('Oidc','ForwardAuth','Saml'));
CREATE TABLE saml_client_configs (
 client_id bigint PRIMARY KEY REFERENCES clients(id), revision bigint NOT NULL DEFAULT 1,
 entity_id text NOT NULL, name_id_format text NOT NULL,
 require_signature boolean NOT NULL DEFAULT false, attributes jsonb NOT NULL DEFAULT '{}',
 launch_url text NOT NULL DEFAULT '', key_overlap_s integer NOT NULL DEFAULT 604800 CHECK(key_overlap_s BETWEEN 180 AND 2678400)
);
CREATE TABLE saml_acs_endpoints (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, client_id bigint NOT NULL REFERENCES clients(id),
 endpoint_index integer NOT NULL CHECK(endpoint_index>=0), url text NOT NULL, is_default boolean NOT NULL DEFAULT false,
 UNIQUE(client_id,endpoint_index), UNIQUE(client_id,url)
);
CREATE UNIQUE INDEX ON saml_acs_endpoints(client_id) WHERE is_default;
CREATE TABLE saml_sp_certificates (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, client_id bigint NOT NULL REFERENCES clients(id), certificate bytea NOT NULL
);
CREATE TABLE saml_signing_keys (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, client_id bigint NOT NULL REFERENCES clients(id),
 key_ref text NOT NULL UNIQUE, private_key text NOT NULL, certificate bytea NOT NULL,
 state text NOT NULL CHECK(state IN ('active','next','retired')), expires_at timestamptz NOT NULL,
 retire_at timestamptz, retired_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ON saml_signing_keys(client_id) WHERE state='active';
CREATE UNIQUE INDEX ON saml_signing_keys(client_id) WHERE state='next';
CREATE TABLE saml_subjects (
 client_id bigint NOT NULL REFERENCES clients(id), user_id bigint NOT NULL REFERENCES users(id), subject text NOT NULL,
 PRIMARY KEY(client_id,user_id), UNIQUE(client_id,subject)
);
CREATE TABLE saml_requests (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, client_id bigint NOT NULL REFERENCES clients(id),
 request_id text NOT NULL, token_hash text NOT NULL UNIQUE, browser_hash text NOT NULL,
 revision bigint NOT NULL, request jsonb NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(client_id,request_id)
);
CREATE INDEX ON saml_requests(expires_at);
CREATE TABLE saml_sessions (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, client_id bigint NOT NULL REFERENCES clients(id),
 session_id bigint NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, session_index text NOT NULL UNIQUE,
 UNIQUE(client_id,session_id)
);
-- Serialize policy changes with issuance. Statement locks also cover empty
-- membership/rule sets, where row locks alone cannot prevent phantom grants.
-- Issuance acquires SHARE locks on these tables in a fixed order.
CREATE FUNCTION guard_saml_client_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE saml_client_configs SET revision=revision+1 WHERE client_id=NEW.id;
 RETURN NEW;
END; $$;
CREATE TRIGGER guard_saml_client AFTER UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION guard_saml_client_changed();
-- Proof that a session came from this request's explicitly forced login.
-- No FK to the request: replay reservations expire before Guard sessions do.
CREATE TABLE saml_authentications (
 session_id bigint PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
 request_hash text NOT NULL
);
