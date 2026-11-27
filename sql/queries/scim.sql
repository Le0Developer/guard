-- name: GetSCIMConfig :one
SELECT * FROM scim_configs WHERE client_id=$1;

-- name: SaveSCIMConfig :one
INSERT INTO scim_configs (client_id,endpoint,secret,enabled,group_patterns) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (client_id) DO UPDATE SET
 generation=scim_configs.generation + CASE WHEN scim_configs.endpoint<>EXCLUDED.endpoint THEN 1 ELSE 0 END,
 endpoint=EXCLUDED.endpoint,secret=EXCLUDED.secret,enabled=EXCLUDED.enabled,group_patterns=EXCLUDED.group_patterns,
 revision=scim_configs.revision+1,work_revision=0,snapshot='[]',cursor=0,
 attempts=0,blocked=false,last_error='',next_attempt_at=now(),lease_token='',lease_until=NULL,
 last_success_at=CASE WHEN scim_configs.endpoint<>EXCLUDED.endpoint THEN NULL ELSE scim_configs.last_success_at END
RETURNING *;

-- name: RequestSCIMSync :execrows
UPDATE scim_configs SET revision=revision+1,blocked=false,attempts=0,last_error='',next_attempt_at=now() WHERE client_id=$1 AND enabled;

-- name: ClaimSCIM :one
WITH candidate AS (
 SELECT s.client_id FROM scim_configs s JOIN clients c ON c.id=s.client_id
 WHERE s.enabled AND NOT s.blocked AND c.deleted_at IS NULL AND c.client_type='Oidc'
 AND s.next_attempt_at<=now() AND (s.lease_until IS NULL OR s.lease_until<now())
 ORDER BY s.next_attempt_at,s.client_id LIMIT 1 FOR UPDATE OF s SKIP LOCKED
)
UPDATE scim_configs s SET lease_token=$1,lease_until=now()+interval '2 minutes'
FROM candidate c WHERE s.client_id=c.client_id RETURNING s.*;

-- name: FenceSCIM :execrows
UPDATE scim_configs SET lease_until=now()+interval '2 minutes'
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: SetSCIMSnapshot :execrows
UPDATE scim_configs SET snapshot=$4,cursor=0,work_revision=$5
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: ListSCIMMappings :many
SELECT * FROM scim_mappings WHERE client_id=$1 AND generation=$2 ORDER BY kind,external_id;

-- name: PutSCIMMapping :execrows
INSERT INTO scim_mappings(client_id,generation,kind,external_id,remote_id)
SELECT s.client_id,s.generation,$4,$5,$6 FROM scim_configs s
WHERE s.client_id=$1 AND s.generation=$2 AND s.lease_token=$3 AND s.enabled AND s.lease_until>now()
ON CONFLICT (client_id,generation,kind,external_id) DO UPDATE SET remote_id=EXCLUDED.remote_id;

-- name: RemoveSCIMMapping :execrows
DELETE FROM scim_mappings m USING scim_configs s
WHERE m.client_id=s.client_id AND m.generation=s.generation AND s.client_id=$1 AND s.generation=$2
AND s.lease_token=$3 AND s.enabled AND s.lease_until>now() AND m.kind=$4 AND m.external_id=$5;

-- name: AdvanceSCIM :execrows
UPDATE scim_configs SET cursor=$4
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: ReleaseSCIM :execrows
UPDATE scim_configs SET lease_token='',lease_until=NULL,next_attempt_at=now()
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: CompleteSCIM :execrows
UPDATE scim_configs SET lease_token='',lease_until=NULL,snapshot='[]',cursor=0,work_revision=0,
 last_success_at=now(),last_error='',attempts=0,blocked=false,
 next_attempt_at=CASE WHEN revision=work_revision THEN now()+interval '15 minutes' ELSE now() END
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: FailSCIM :execrows
UPDATE scim_configs SET lease_token='',lease_until=NULL,attempts=attempts+1,last_error=$4,
 blocked=$5 AND revision=$6,next_attempt_at=CASE WHEN revision<>$6 THEN now() ELSE $7 END
WHERE client_id=$1 AND generation=$2 AND lease_token=$3 AND enabled AND lease_until>now();

-- name: EnsureSCIMIntent :execrows
INSERT INTO scim_mappings(client_id,generation,kind,external_id,remote_id)
SELECT s.client_id,s.generation,$4,$5,'' FROM scim_configs s
WHERE s.client_id=$1 AND s.generation=$2 AND s.lease_token=$3 AND s.enabled AND s.lease_until>now()
ON CONFLICT (client_id,generation,kind,external_id) DO UPDATE SET remote_id=scim_mappings.remote_id;
