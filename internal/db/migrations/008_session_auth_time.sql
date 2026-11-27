-- Session creation is not proof of a fresh upstream authentication.
ALTER TABLE sessions ADD COLUMN auth_time bigint NOT NULL DEFAULT (extract(epoch FROM now())::bigint);
UPDATE sessions s SET auth_time = CASE
    WHEN EXISTS (SELECT 1 FROM upstream_sessions u WHERE u.session_id = s.id) THEN 0
    ELSE extract(epoch FROM s.created_at)::bigint
END;
