-- Drop user_org_project_roles table and indexes
DROP INDEX IF EXISTS idx_user_org_project_roles_project_id;

DROP INDEX IF EXISTS idx_user_org_project_roles_org_id;

DROP INDEX IF EXISTS idx_user_org_project_roles_user_id;

DROP TABLE IF EXISTS user_org_project_roles;