-- Drop projects table and indexes
DROP INDEX IF EXISTS idx_projects_org_id;

DROP INDEX IF EXISTS idx_projects_tenant_id;

DROP TABLE IF EXISTS projects;