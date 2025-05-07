-- Remove permissions JSONB column from admin_roles
ALTER TABLE admin_roles
DROP COLUMN IF EXISTS permissions;