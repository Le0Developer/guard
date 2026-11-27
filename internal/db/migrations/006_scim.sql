CREATE TABLE scim_configs (
    client_id bigint PRIMARY KEY REFERENCES clients(id),
    endpoint text NOT NULL,
    secret text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    generation bigint NOT NULL DEFAULT 1,
    revision bigint NOT NULL DEFAULT 1,
    work_revision bigint NOT NULL DEFAULT 0,
    snapshot jsonb NOT NULL DEFAULT '[]',
    cursor integer NOT NULL DEFAULT 0,
    attempts integer NOT NULL DEFAULT 0,
    blocked boolean NOT NULL DEFAULT false,
    last_error text NOT NULL DEFAULT '',
    last_success_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_token text NOT NULL DEFAULT '',
    lease_until timestamptz
);
CREATE TABLE scim_mappings (
    client_id bigint NOT NULL REFERENCES scim_configs(client_id),
    generation bigint NOT NULL,
    kind text NOT NULL CHECK (kind IN ('Users','Groups')),
    external_id text NOT NULL,
    -- Empty ID records a durable possible-create intent before HTTP.
    remote_id text NOT NULL DEFAULT '',
    PRIMARY KEY (client_id,generation,kind,external_id)
);
CREATE UNIQUE INDEX ON scim_mappings(client_id,generation,kind,remote_id) WHERE remote_id<>'';
CREATE INDEX ON scim_configs(next_attempt_at) WHERE enabled AND NOT blocked;

-- All authoritative directory changes mark reconciliation dirty in the same
-- transaction. Existing snapshots finish first, then the newer revision runs.
CREATE FUNCTION guard_scim_directory_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE scim_configs SET revision=revision+1, next_attempt_at=now(),
        blocked=false WHERE enabled;
    RETURN NULL;
END;
$$;
CREATE TRIGGER guard_scim_users AFTER INSERT OR DELETE OR UPDATE OF username,email,disabled,deleted_at ON users
FOR EACH STATEMENT EXECUTE FUNCTION guard_scim_directory_changed();
CREATE TRIGGER guard_scim_groups AFTER INSERT OR DELETE OR UPDATE OF name,deleted_at ON groups
FOR EACH STATEMENT EXECUTE FUNCTION guard_scim_directory_changed();
CREATE TRIGGER guard_scim_members AFTER INSERT OR UPDATE OR DELETE ON group_members
FOR EACH STATEMENT EXECUTE FUNCTION guard_scim_directory_changed();
CREATE TRIGGER guard_scim_rules AFTER INSERT OR UPDATE OR DELETE ON client_access_rules
FOR EACH STATEMENT EXECUTE FUNCTION guard_scim_directory_changed();

CREATE FUNCTION guard_scim_client_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL OR NEW.client_type <> 'Oidc' THEN
        UPDATE scim_configs SET enabled=false, generation=generation+1,
            snapshot='[]', cursor=0, work_revision=0, lease_token='',lease_until=NULL
        WHERE client_id=NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER guard_scim_client AFTER UPDATE OF client_type,deleted_at ON clients
FOR EACH ROW EXECUTE FUNCTION guard_scim_client_changed();
