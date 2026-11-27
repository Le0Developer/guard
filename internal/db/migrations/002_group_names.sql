-- Application checks provide friendly feedback; this also protects concurrent writes.
CREATE UNIQUE INDEX groups_active_name_key ON groups (lower(name)) WHERE deleted_at IS NULL;
