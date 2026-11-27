-- Keep the current usable signing key when upgrading from staged rotation.
DELETE FROM saml_signing_keys WHERE private_key='';
DELETE FROM saml_signing_keys WHERE id IN (
 SELECT id FROM (
  SELECT id,row_number() OVER(PARTITION BY client_id ORDER BY (state='active') DESC,created_at DESC,id DESC) AS position
  FROM saml_signing_keys
 ) ranked WHERE position>1
);
DROP INDEX IF EXISTS saml_signing_keys_client_id_idx;
DROP INDEX IF EXISTS saml_signing_keys_client_id_idx1;
ALTER TABLE saml_signing_keys ADD UNIQUE(client_id);
ALTER TABLE saml_signing_keys DROP COLUMN state, DROP COLUMN expires_at, DROP COLUMN retire_at, DROP COLUMN retired_at;
ALTER TABLE saml_client_configs DROP COLUMN key_overlap_s, DROP COLUMN attributes;
-- Pending requests must restart under the fixed attribute contract.
UPDATE saml_client_configs SET revision=revision+1;
