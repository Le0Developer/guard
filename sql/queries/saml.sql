-- name: GetSAMLConfig :one
SELECT * FROM saml_client_configs WHERE client_id=$1;
-- name: SaveSAMLConfig :one
INSERT INTO saml_client_configs(client_id,entity_id,name_id_format,require_signature,attributes,launch_url,key_overlap_s)
VALUES($1,$2,$3,$4,$5,$6,COALESCE(NULLIF(sqlc.arg(key_overlap_s)::integer,0),604800)) ON CONFLICT(client_id) DO UPDATE SET entity_id=EXCLUDED.entity_id,name_id_format=EXCLUDED.name_id_format,require_signature=EXCLUDED.require_signature,attributes=EXCLUDED.attributes,launch_url=EXCLUDED.launch_url,key_overlap_s=EXCLUDED.key_overlap_s,revision=saml_client_configs.revision+1 RETURNING *;
-- name: BumpSAMLRevision :exec
UPDATE saml_client_configs SET revision=revision+1 WHERE client_id=$1;
-- name: SAMLACS :many
SELECT * FROM saml_acs_endpoints WHERE client_id=$1 ORDER BY endpoint_index;
-- name: DeleteSAMLACS :exec
DELETE FROM saml_acs_endpoints WHERE client_id=$1;
-- name: CreateSAMLACS :exec
INSERT INTO saml_acs_endpoints(client_id,endpoint_index,url,is_default) VALUES($1,$2,$3,$4);
-- name: SAMLSPCertificates :many
SELECT * FROM saml_sp_certificates WHERE client_id=$1 ORDER BY id;
-- name: DeleteSAMLSPCertificates :exec
DELETE FROM saml_sp_certificates WHERE client_id=$1;
-- name: CreateSAMLSPCertificate :exec
INSERT INTO saml_sp_certificates(client_id,certificate) VALUES($1,$2);
-- name: SAMLKeys :many
SELECT * FROM saml_signing_keys WHERE client_id=$1 AND (state<>'retired' OR retire_at>now()) ORDER BY id;
-- name: CreateSAMLKey :one
INSERT INTO saml_signing_keys(client_id,key_ref,private_key,certificate,state,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING *;
-- name: RetireSAMLKey :exec
UPDATE saml_signing_keys SET state='retired',retired_at=now(),retire_at=now()+make_interval(secs => sqlc.arg(overlap_s)::double precision) WHERE client_id=sqlc.arg(client_id) AND state='active';
-- name: ActivateSAMLKey :execrows
UPDATE saml_signing_keys SET state='active' WHERE client_id=$1 AND state='next' AND expires_at>now();
-- name: CleanSAML :exec
DELETE FROM saml_requests WHERE expires_at<now();
-- name: EraseSAMLRetiredSecrets :exec
UPDATE saml_signing_keys SET private_key='' WHERE state='retired' AND private_key<>'' AND retired_at<now()-interval '3 minutes';
-- name: CreateSAMLRequest :one
INSERT INTO saml_requests(client_id,request_id,token_hash,browser_hash,revision,request,expires_at)
SELECT $1,$2,$3,$4,$5,$6,$7 WHERE (SELECT count(*) FROM saml_requests WHERE expires_at>now() AND consumed_at IS NULL)<10000 AND (SELECT count(*) FROM saml_requests WHERE client_id=$1 AND expires_at>now() AND consumed_at IS NULL)<500 AND (SELECT count(*) FROM saml_requests WHERE browser_hash=$4 AND expires_at>now() AND consumed_at IS NULL)<20
RETURNING *;
-- name: GetSAMLRequest :one
SELECT * FROM saml_requests WHERE token_hash=$1;
-- name: LockSAMLRequest :one
SELECT * FROM saml_requests WHERE token_hash=$1 FOR UPDATE;
-- name: ConsumeSAMLRequest :exec
UPDATE saml_requests SET consumed_at=now() WHERE id=$1;
-- name: GetSAMLSubject :one
SELECT subject FROM saml_subjects WHERE client_id=$1 AND user_id=$2;
-- name: CreateSAMLSubject :one
INSERT INTO saml_subjects(client_id,user_id,subject) VALUES($1,$2,$3) ON CONFLICT(client_id,user_id) DO UPDATE SET subject=saml_subjects.subject RETURNING subject;
-- name: SAMLSession :one
INSERT INTO saml_sessions(client_id,session_id,session_index) VALUES($1,$2,$3) ON CONFLICT(client_id,session_id) DO UPDATE SET session_index=saml_sessions.session_index RETURNING *;
-- name: LockSAMLPolicy :exec
LOCK TABLE group_members,groups,client_access_rules IN SHARE MODE;
-- name: RecordSAMLAuthentication :exec
INSERT INTO saml_authentications(session_id,request_hash) VALUES($1,$2);
-- name: HasSAMLAuthentication :one
SELECT EXISTS(SELECT 1 FROM saml_authentications WHERE session_id=$1 AND request_hash=$2);
-- name: LockSAMLAdmission :exec
SELECT pg_advisory_xact_lock(1936028272);
