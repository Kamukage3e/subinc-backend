# RBAC Management Migrations

All schema migrations for rbac-management are in this folder. Each migration is production-grade, type-safe, and supports multi-tenancy.

## Tables
- roles
- permissions
- role_bindings
- policies
- api_permissions
- resources
- audit_log
- abac_policies
- delegated_roles
- permission_templates

All migrations are reviewed for SaaS readiness before merge. No placeholders, no bloat, no non-prod content. 