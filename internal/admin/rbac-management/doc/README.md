# RBAC Management Documentation

## API
- All endpoints are defined in `openapi.yaml` (OpenAPI 3.1)
- Endpoints: /roles, /permissions, /role-bindings, /policies, /api-permissions, /resources, /delegations, /permission-templates, /restore, /bulk, /simulate, /import, /export
- All endpoints are RBAC-protected, JWT-secured, and auditable

## Migrations
- All schema migrations are in `../migration/`
- Tables: roles, permissions, role_bindings, policies, api_permissions, resources, audit_log, abac_policies, delegated_roles, permission_templates
- All tables are multi-tenant, type-safe, and production-grade

## OpenAPI
- See `openapi.yaml` for full schema, request/response types, and error handling

## Enforcement
- No placeholders, no bloat, no non-prod content
- All code and docs are production-grade, real, and ready for SaaS deployment 