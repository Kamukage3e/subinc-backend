# Subinc Cost Microservice Backend

```
+-------------------+         +-------------------+         +-------------------+
|    Admin Panel    | <-----> |    API Gateway    | <-----> |   Client Panel    |
+-------------------+         +-------------------+         +-------------------+
         |                            |                              |
         v                            v                              v
+-------------------+   +---------------------------+   +-----------------------+
|   Auth (OIDC/JWT) |   |  Feature Flags/Settings   |   |   Server Config API   |
+-------------------+   +---------------------------+   +-----------------------+
         |                            |                              |
         v                            v                              v
+-------------------+   +---------------------------+   +-----------------------+
|   RBAC & Security |   |  Tenant Isolation Layer   |   |   Audit Logging       |
+-------------------+   +---------------------------+   +-----------------------+
         |                            |                              |
         v                            v                              v
+-------------------+   +---------------------------+   +-----------------------+
|   Postgres (DB)   |   |   Redis (Cache/Jobs)      |   |   Asynq (Jobs)        |
+-------------------+   +---------------------------+   +-----------------------+
```

## Overview
This is a production-grade, multi-tenant SaaS backend for Admin Panel as a Service. It is designed for real-world, high-scale, secure, and extensible deployments. All configuration, feature flags, and tenant isolation are runtime, DB-backed, and auditable. No static config, no YAML, no placeholders.

---

## Features

### Client (Tenant) Features
- **Self-Service Admin Panel**: Each tenant gets a secure, isolated admin panel to manage their own users, billing, projects, and settings.
- **Per-Tenant Feature Flags**: Tenants can enable/disable features (e.g., billing, AI, custom reports) via their own settings. All flags are stored in the DB and take effect at runtime.
- **Per-Tenant Limits**: Tenants can set and view their own usage limits (e.g., max users, max projects) and upgrade as needed.
- **Bring Your Own Database/Infra**: Tenants can securely provide their own DB connection info and cloud credentials. All data access and integrations are routed through tenant-specific infra, with strict isolation and credential management.
- **Audit Logging**: All config changes, feature toggles, and sensitive actions are logged and auditable per tenant.
- **Secure API Access**: All APIs are protected by JWT/OIDC, RBAC, and rate limiting. No tenant can access another tenant's data or config.
- **Runtime Config Management**: Tenants can update their own settings, feature flags, and infra config at any time via API/UI. No restarts, no static files.

### Owner (Platform Admin) Features
- **Global Feature Flags & Rollouts**: Platform owner can enable/disable features globally or for specific tenants using the `server_config` module. All changes are runtime, versioned, and auditable.
- **Per-Tenant Overrides**: Owner can override tenant settings, set defaults, and enforce limits via secure admin APIs.
- **Multi-Tenant Isolation**: All tenant data, config, and infra are strictly isolated at the service and DB layer. No cross-tenant access.
- **Bring-Your-Own-Infra Control**: Owner can enable/disable tenant BYO-DB/BYO-cloud, rotate/revoke credentials, and audit all infra changes.
- **Operational Controls**: Owner can set global rate limits, maintenance windows, and operational toggles via the server config API.
- **Audit & Compliance**: All admin actions are logged, versioned, and auditable. No silent failures, no insecure defaults.
- **Hot-Reloadable Config**: All server config is cached in-memory and hot-reloaded on change. No downtime, no redeploys.
- **RBAC & Security**: Full RBAC for both platform and tenant admins. All APIs are secure by default. No hardcoded secrets, no insecure defaults.

---

## Tech Stack
- **Language**: Go (latest stable)
- **API Framework**: Fiber (RESTful, idiomatic Go)
- **Database**: Postgres (multi-tenant, per-tenant settings, audit logs)
- **Cache/Jobs**: Redis (sessions, cache, background jobs via Asynq)
- **Auth**: JWT/OIDC, RBAC, per-tenant and global rate limiting
- **Logging**: Zap (structured, contextual, production-grade)
- **Metrics**: Prometheus (jobs, sessions, cache, API)
- **Config**: All runtime, DB-backed, hot-reloadable (no YAML, no static config)
- **Containerization**: Cloud-native, ready for Docker/K8s/CI/CD
- **Security**: No hardcoded secrets, all credentials encrypted at rest, never logged
- **Testing**: All code is modular, interface-driven, and CI/CD ready

---

## Architectural Decisions
- **No static config**: All settings, feature flags, and infra are runtime, DB-backed, and auditable.
- **Strict multi-tenancy**: All tenant data and config are isolated at the service and DB layer. No cross-tenant access.
- **RBAC everywhere**: All APIs are protected by RBAC and rate limiting. No insecure endpoints.
- **Audit everything**: All sensitive actions are logged and versioned. No silent failures.
- **No placeholders, no bloat**: All code is production-grade, real, and ready for SaaS deployment. No commented-out code, no TODOs, no legacy.
- **Cloud-native**: All code is ready for containerization, orchestration, and CI/CD.

---

## How It Works
- **Per-Tenant Config**: Stored as JSON in the `settings` column of the `tenants` table. All feature flags, limits, and preferences are runtime, DB-backed, and modifiable via API/UI.
- **Server Config**: All global/operational settings are managed via the `server_config` table and API. Hot-reloadable, versioned, and auditable.
- **Bring Your Own Infra**: Tenants can securely provide their own DB/cloud credentials. All access is dynamic, secure, and auditable.
- **Admin APIs**: Both tenant and platform admins have secure APIs to manage all config, features, and infra at runtime.

---

## No Frontend
This repo is backend-only. No frontend code, no UI scaffolding, no non-prod content.

---

## Enforcement
- No placeholder files or folders anywhere in the repo.
- No mixing of prod and non-prod code in the same directory.
- No "example", "sample", or "test" code outside of dedicated test directories.
- All new code and structure must be reviewed for real-world SaaS readiness before merge.

---

For expert-level backend SaaS engineers only. All code and documentation are production-grade, secure, and ready for real-world deployment.

## Configuration

All configuration, feature flags, and credentials are DB-backed and hot-reloadable at runtime. No static config files or YAML are used. The only exception is the initial database bootstrap, which requires the OWNER_DB_DSN environment variable to connect to the owner database. All other config is managed via the `server_config` table (for owner-admin) and the `settings` column in the `tenants` table (for client-admin), and can be updated at runtime via API. All changes are immediately effective and auditable.

## Configuration Keys, Secrets, and Credentials

> **Standard:** All credentials/settings (DB, Redis, AWS, SMTP, payment, etc.) must be runtime-configurable via HTTP API for both owner-admin and client-admin. After update, the app must test the connection and return the result. All config is DB-backed and hot-reloadable using the server_config table. No static config except OWNER_DB_DSN. 

| Key / Header / Config         | Source                | Purpose / Usage                                 | Security Notes                                  |
|------------------------------|-----------------------|-------------------------------------------------|-------------------------------------------------|
| OWNER_DB_DSN                | Env                   | Owner DB bootstrap DSN (only required static config) | Must be set for owner-admin boot                |
| PORT                         | Env                   | HTTP server port                                | Defaults to 8080 if unset                       |
| X-DB-Host                    | HTTP Header           | DB host (client-admin)                          | Required for multi-tenant DB routing            |
| X-DB-Port                    | HTTP Header           | DB port (client-admin)                          | Required for multi-tenant DB routing            |
| X-DB-User                    | HTTP Header           | DB user (client-admin)                          | Required for multi-tenant DB routing            |
| X-DB-Password                | HTTP Header           | DB password (client-admin)                      | Required for multi-tenant DB routing            |
| X-DB-Name                    | HTTP Header           | DB name (client-admin)                          | Required for multi-tenant DB routing            |
| X-DB-SSLMode                 | HTTP Header           | DB SSL mode (client-admin)                      | Required for multi-tenant DB routing            |
| X-JWT-Secret                 | HTTP Header           | JWT secret (client-admin)                       | Required for client-admin auth                  |
| X-Log-Format                 | HTTP Header           | Log format (client-admin)                       | Optional, defaults to json                      |
| X-Log-Color                  | HTTP Header           | Log color (client-admin)                        | Optional, defaults to false                     |
| X-Log-Service                | HTTP Header           | Log service name (client-admin)                 | Optional, defaults to client                    |
| X-Log-Env                    | HTTP Header           | Log environment (client-admin)                  | Optional, defaults to prod                      |
| db.* (host, port, user, ...) | server_config table, API | DB connection for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| logging.*                    | server_config table, API | Logging config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| jwt.secret_name              | server_config table, API | JWT secret name for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| oauth.google.*               | server_config table, API | Google OAuth client config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| saml.*                       | server_config table, API | SAML config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| redis.*                      | server_config table, API | Redis connection config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| aws.*                        | server_config table, API | AWS credentials and role ARN for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| stripe_api_key, paypal_client_id/secret, googlepay_*/applepay_* | server_config table, API | Payment provider config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| braintree.*                  | server_config table, API | Braintree API credentials (merged into payment provider config) | Managed via API, never static, owner/client specific |
| openai.api_key               | server_config table, API | OpenAI config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| admin.email/username/password| server_config table, API | Initial admin credentials for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| hashid_salt                  | server_config table, API | Hashid salt for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| Any key in server_config     | DB table, API         | Hot-reloadable runtime config                   | Set via API, never hardcoded                    |
| Any key in billing_config    | DB table, API         | Billing config (fees, rates, etc)               | Set via API, never hardcoded                    |
| Provider secrets (email/sms) | secret store          | Email/SMS/Chat provider credentials             | Loaded per-tenant, never hardcoded              |
| user_api_keys.*               | DB table, API         | Per-user API keys (create, list, revoke)        | Never exposed in logs, only shown at creation   |
| notification_configs.*        | DB table, API         | Per-tenant notification config (channels, events, recipients, enabled) | All secrets stored encrypted, never logged      |
| provider_secrets (email/sms/chat) | DB table, API     | Per-tenant provider secrets (tokens, webhooks, credentials) | Loaded at runtime, never hardcoded              |
| security_event_webhooks.secret| DB table, API         | Per-tenant webhook secret for HMAC signing       | Used for event verification, never exposed      |
| users.password_hash           | DB table              | User password hashes (bcrypt/argon2)             | Never exposed, only set/reset via secure flows  |
| session_keys (Redis)          | Redis, per-tenant     | Per-session keys for user/session management    | Never logged, auto-expire, secure by default    |
| password_reset_tokens        | DB table, API         | Password reset tokens (per-user, time-limited)  | Never logged, only valid for short duration     |
| jwt_tokens                   | API, bearerFormat:JWT | JWT tokens for API auth (user, admin, tenant)   | Never logged, short-lived, bearer only          |
| rate_limit_config            | DB table, API         | Per-tenant rate limit config                    | Runtime, hot-reloadable, never hardcoded        |
| plugin_config                | DB table, API         | Per-tenant plugin config                        | Runtime, hot-reloadable, never hardcoded        |
| currency_config              | DB table, API         | Per-tenant currency config                      | Runtime, hot-reloadable, never hardcoded        |
| cors.*                       | server_config table, API | CORS config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| session.*                    | server_config table, API | Session config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |
| webhook.*                    | server_config table, API | Webhook config for owner-admin (runtime, hot-reloadable) | Managed via API, never static, owner-admin only |

**Security:**
- All secrets must be loaded from environment variables, secret stores, or secure config files.
- Never commit real secrets to version control.
- Rotate credentials regularly and use least privilege for all service accounts.
- All config changes are auditable via the server_config and billing_config history tables.

## Configuration Testing

The system automatically verifies all credentials and configurations when they are updated, providing immediate feedback on whether the updated configuration is valid and can establish connections properly:

| Configuration Type    | Testing Method                                      | Validation Response                              |
|-----------------------|-----------------------------------------------------|--------------------------------------------------|
| DB Connections        | Tests connection by creating a pool and pinging     | Returns connection success/error with diagnostic info |
| Redis Connections     | Establishes connection and performs PING command    | Returns connection success/error with diagnostic info |
| AWS Credentials       | Validates via STS GetCallerIdentity API call        | Returns authentication success/error and account info |
| SMTP Server           | Tests connection with appropriate SSL/TLS settings  | Returns connection success/error with specific SMTP error info |
| JWT Secrets           | Creates and validates a test token                  | Returns token creation and validation success/error |
| OAuth Credentials     | Tests token endpoint with provided client credentials | Returns validation status with provider-specific details |
| SAML Configuration    | Fetches metadata URL and validates XML content      | Returns metadata availability and SAML format validation |
| Payment Providers     | Tests API connectivity for each configured provider | Returns per-provider connection status |
| OpenAI API Keys       | Tests models API endpoint with provided credentials | Returns API key validation status |
| Webhook Endpoints     | Tests both HEAD and POST requests with test payload | Returns endpoint reachability status |

All validation results include the original configuration (with sensitive data redacted in logs) and detailed error information when connections fail, enabling quick troubleshooting of configuration issues. This system ensures that no invalid credentials or configurations can be saved without the user being notified of potential problems.

**Implementation Details:**
- Connection tests are implemented in the `providercheck` package with standardized interfaces
- All tests include appropriate timeouts to prevent hanging requests
- Tests use minimal API calls to validate credentials without excessive permissions
- Validation responses include structured error information for frontend display
- Tests are performed automatically upon configuration update without requiring separate API calls

## GraphQL Integration

- Production GraphQL API for document management is provided via the `doc-management` module.
- Endpoint: `/api/v1/doc-graphql`
- Powered by gqlgen, fully type-safe, modular, and isolated from admin management modules.
- No code mixing with admin, billing, user, org, project, or tenant management.

## Directory Structure

- `internal/doc-management/` — All document management and GraphQL integration code. No code mixing with admin management modules.

> All document management and GraphQL code must reside in `internal/doc-management`. No code mixing with admin management modules. This is enforced for production SaaS quality.

> To extend GraphQL, add new types, resolvers, and schema only in `internal/doc-management`. Never touch admin management code for doc GraphQL. This is a hard rule for maintainability and security.

> All doc-management GraphQL endpoints are versioned and isolated. Endpoint: `/api/v1/doc-graphql`. No shared handlers or stores with admin modules. This is enforced for SaaS-grade modularity.

> All doc-management code is linter-clean, type-safe, and passes static analysis. No commented-out code, no TODOs, no placeholders. This is enforced for production SaaS quality.

> All doc-management code is cloud-native, container-ready, and CI/CD friendly. No legacy or bloat. This is enforced for SaaS deployment.

> All doc-management code is accessible and maintainable by any senior engineer without additional context. This is enforced for SaaS maintainability.

> All doc-management code follows strict Go, Fiber, and SaaS backend best practices. No exceptions. This is enforced for production quality.

> All doc-management code is reviewed for real-world SaaS readiness before merge. No exceptions. This is enforced for production deployment.

> All doc-management code is secure by default. No hardcoded secrets, no insecure defaults, no panics. This is enforced for SaaS security.

> All doc-management code is easily testable and ready for CI/CD integration. No exceptions. This is enforced for SaaS quality.

> All doc-management code is compatible with the latest stable versions of all relevant tools and languages. This is enforced for SaaS compatibility.

> All doc-management code is documented for expert-level developers. No hand-holding, no redundant explanations, no beginner content. This is enforced for SaaS documentation quality.

> All doc-management code must not violate any of the SaaS backend rules listed above. This is enforced for production SaaS quality.



curl -X POST http://localhost:8080/api/v1/owner-admin/auth/login -H "Content-Type: application/json" -d '{"email":"admin@subinc.com","password":"admin"}'
{"expires_at":"2025-05-14T13:40:43.068797Z","refresh_token":"2iF29XRrOVAI9YVoDLEH09ieT_1NgRUk3YdA4IFMnns=","session_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDcyMzAwNDMsImlhdCI6MTc0NzE0MzY0MywidGVuYW50X2lkIjoiIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyJ9.WBFftT34E3ViWNH9zl2jCyNMtT0hThCPKGRDbxCvd6Y"}% 


atlas schema apply --env local