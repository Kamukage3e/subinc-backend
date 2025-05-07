-- Add permissions JSONB column to admin_roles for flexible RBAC
ALTER TABLE admin_roles
ADD COLUMN permissions JSONB NOT NULL DEFAULT '[]';