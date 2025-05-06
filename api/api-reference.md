# Subinc Cost Management API Reference

## Client User APIs

### Users
- **GET /users** — List users
  - Query: None
  - Response: `[User]`
  - Auth: Required
- **POST /users** — Register user
  - Body: `{ username, email, password, tenant_id }`
  - Response: `User`
  - Auth: None
- **POST /users/login** — User login
  - Body: `{ username, password }`
  - Response: `{ token }`
  - Auth: None
- **GET /users/{id}** — Get user by ID
  - Path: `id`
  - Response: `User`
  - Auth: Required
- **PUT /users/{id}** — Update user
  - Path: `id`
  - Body: `{ email?, password?, roles?, attributes? }`
  - Response: `User`
  - Auth: Required
- **DELETE /users/{id}** — Delete user
  - Path: `id`
  - Response: 204 No Content
  - Auth: Required
- **POST /users/{id}/roles** — Assign role
  - Path: `id`
  - Body: `{ role }`
  - Response: `{ roles }`
  - Auth: Admin/Owner
- **DELETE /users/{id}/roles/{role}** — Remove role
  - Path: `id`, `role`
  - Response: `{ roles }`
  - Auth: Admin/Owner
- **POST /users/{id}/attributes** — Set attribute
  - Path: `id`
  - Body: `{ key, value }`
  - Response: `{ attributes }`
  - Auth: Admin/Owner
- **DELETE /users/{id}/attributes/{key}** — Remove attribute
  - Path: `id`, `key`
  - Response: `{ attributes }`
  - Auth: Admin/Owner

### Tenants
- **GET /tenants** — List tenants
  - Response: `[Tenant]`
  - Auth: Required
- **GET /tenants/{id}** — Get tenant by ID
  - Path: `id`
  - Response: `Tenant`
  - Auth: Required
- **DELETE /tenants/{id}** — Delete tenant
  - Path: `id`
  - Response: 204 No Content
  - Auth: Required

### Projects
- **POST /projects** — Create project
  - Body: `ProjectCreate`
  - Response: `Project`
  - Auth: Required
- **GET /projects/{id}** — Get project by ID
  - Path: `id`
  - Response: `Project`
  - Auth: Required
- **PUT /projects/{id}** — Update project
  - Path: `id`
  - Body: `ProjectUpdate`
  - Response: `Project`
  - Auth: Required
- **DELETE /projects/{id}** — Delete project
  - Path: `id`
  - Response: 204 No Content
  - Auth: Required
- **GET /tenants/{tenant_id}/projects** — List projects by tenant
  - Path: `tenant_id`
  - Response: `[Project]`
  - Auth: Required
- **GET /orgs/{org_id}/projects** — List projects by org
  - Path: `org_id`
  - Response: `[Project]`
  - Auth: Required

### Cost, Budgets, Anomalies, Forecasts, Cloud, Billing, Credits, Refunds, Invoices, Payments, Coupons, Discounts, Webhooks, Provisioning, Architecture, Optimization, Health, Rate Limit, Logging, CORS, OPA
- All endpoints under `/cost`, `/billing`, `/credits`, `/refunds`, `/invoices`, `/payments`, `/coupons`, `/discounts`, `/webhook-events`, `/provisioning`, `/architecture`, `/optimization`, `/health`, `/cloud`, `/webhooks`, `/rate-limit`, `/logging`, `/cors`, `/opa/authorize` are available to authenticated users. See OpenAPI YAML for full details on request/response schemas and required fields.

## Admin APIs

All endpoints under `/admin` require admin authentication and RBAC/ABAC as appropriate.

- **GET /admin/users** — List users
- **POST /admin/users** — Create user
- **PUT /admin/users/{id}** — Update user
- **DELETE /admin/users/{id}** — Delete user
- **GET /admin/tenants** — List tenants
- **POST /admin/tenants** — Create tenant
- **PUT /admin/tenants/{id}** — Update tenant
- **DELETE /admin/tenants/{id}** — Delete tenant
- **GET /admin/roles** — List roles
- **POST /admin/roles** — Create role
- **PUT /admin/roles/{id}** — Update role
- **DELETE /admin/roles/{id}** — Delete role
- **GET /admin/permissions** — List permissions
- **POST /admin/permissions** — Create permission
- **PUT /admin/permissions/{id}** — Update permission
- **DELETE /admin/permissions/{id}** — Delete permission
- **GET /admin/sessions** — List sessions
- **POST /admin/sessions/revoke/user** — Revoke all sessions for a user
- **POST /admin/sessions/revoke/tenant** — Revoke all sessions for a tenant
- **POST /admin/mfa/enable** — Enable MFA for a user
- **POST /admin/mfa/disable** — Disable MFA for a user
- **POST /admin/mfa/reset** — Reset MFA for a user
- **GET /admin/mfa/status/{user_id}** — Get MFA status for a user
- **POST /admin/impersonate** — Impersonate a user
- **GET /admin/support/tools** — Get support tools
- **GET /admin/support/user-trace** — Trace user activity
- **GET /admin/support/billing-trace** — Trace billing activity
- **GET /admin/support/impersonation-audit** — List impersonation audit logs
- **GET /admin/rbac** — Get RBAC status
- **GET /admin/delegated-admin** — Get delegated admin status
- **GET /admin/scim** — Get SCIM status
- **GET /admin/audit/anomaly** — List audit anomalies
- **GET /admin/alerts** — List admin alerts
- **GET /admin/abuse** — Get abuse detection status
- **GET /admin/policies** — List admin policies
- **POST /admin/policies** — Create admin policy
- **GET /admin/policies/{id}** — Get admin policy
- **PUT /admin/policies/{id}** — Update admin policy
- **DELETE /admin/policies/{id}** — Delete admin policy
- **POST /admin/roles/{id}/permissions** — Assign permission to role
- **DELETE /admin/roles/{id}/permissions/{perm_id}** — Remove permission from role
- **...and all other /admin endpoints as defined in OpenAPI YAML**

---

**For full request/response schemas, see the OpenAPI YAML (`api/openapi.yaml`). All endpoints are production-ready, RBAC/ABAC enforced, and require proper authentication.** 