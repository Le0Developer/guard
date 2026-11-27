ALTER TABLE clients ADD COLUMN disabled boolean NOT NULL DEFAULT false;

-- Disabling access also reconciles provisioned users as inactive.
CREATE TRIGGER guard_scim_client_disabled AFTER UPDATE OF disabled ON clients
FOR EACH STATEMENT EXECUTE FUNCTION guard_scim_directory_changed();
