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
