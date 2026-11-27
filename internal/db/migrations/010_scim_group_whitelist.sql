-- Preserve existing clients' group scope until an administrator narrows it.
ALTER TABLE scim_configs ADD COLUMN group_patterns text NOT NULL DEFAULT '*';
