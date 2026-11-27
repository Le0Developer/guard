ALTER TABLE clients ADD COLUMN backchannel_logout_uri text NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;

-- RP participation survives access-token cleanup, rotation and revocation.
CREATE TABLE oidc_sessions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id bigint NOT NULL REFERENCES clients(id),
    session_id bigint NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id bigint NOT NULL REFERENCES users(id),
    sid text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id, session_id)
);
CREATE INDEX ON oidc_sessions (session_id);

-- This outbox intentionally has no FK to a Guard session, which has ended.
CREATE TABLE logout_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id bigint NOT NULL REFERENCES clients(id),
    session_id bigint NOT NULL,
    user_id bigint NOT NULL REFERENCES users(id),
    sid text NOT NULL,
    endpoint text NOT NULL,
    jti text NOT NULL UNIQUE,
    attempts integer NOT NULL DEFAULT 0,
    lease_token text NOT NULL DEFAULT '',
    lease_until timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    cancelled_at timestamptz,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(client_id, sid)
);
CREATE INDEX ON logout_deliveries (next_attempt_at) WHERE delivered_at IS NULL AND cancelled_at IS NULL;

-- Every session deletion path (logout, admin/MFA revocation, expiry) cascades
-- through this trigger in the same transaction. A failed enqueue aborts logout.
CREATE FUNCTION guard_queue_backchannel_logout() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO logout_deliveries (client_id, session_id, user_id, sid, endpoint, jti)
    SELECT OLD.client_id, OLD.session_id, OLD.user_id, OLD.sid,
           c.backchannel_logout_uri, 'logout:' || OLD.sid
    FROM clients c WHERE c.id = OLD.client_id AND c.client_type = 'Oidc'
        AND c.deleted_at IS NULL AND c.backchannel_logout_uri <> ''
    ON CONFLICT(client_id, sid) DO NOTHING;
    RETURN OLD;
END;
$$;
CREATE TRIGGER guard_oidc_session_deleted BEFORE DELETE ON oidc_sessions
FOR EACH ROW EXECUTE FUNCTION guard_queue_backchannel_logout();
