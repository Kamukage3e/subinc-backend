-- Drop admin RBAC tables in reverse dependency order
DROP TABLE IF EXISTS admin_user_roles;

DROP TABLE IF EXISTS admin_role_permissions;

DROP TABLE IF EXISTS admin_permissions;

DROP TABLE IF EXISTS admin_roles;

DROP TABLE IF EXISTS admin_users;