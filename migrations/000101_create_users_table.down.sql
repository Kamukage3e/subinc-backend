-- Drop users table and indexes
DROP INDEX IF EXISTS idx_users_email;

DROP INDEX IF EXISTS idx_users_tenant_id;

DROP TABLE IF EXISTS users;