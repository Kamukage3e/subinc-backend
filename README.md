# Subinc Cost Management Microservice – Backend

> NOTE: The `/enterprise` and `/deploy` directories are required for enterprise features and deployment manifests. Create them if missing. See below for details.

## Tech Stack

- **Language:** Go (>=1.23, always latest stable)
- **API Framework:** Fiber (RESTful, idiomatic, high-performance)
- **Database:** PostgreSQL (multi-tenant, ACID, scalable)
- **ORM:** GORM (use raw SQL for perf-critical paths)
- **Cache/Queue:** Redis (caching, rate limiting, background jobs)
- **Cloud SDKs:** AWS SDK for Go v2, Azure SDK for Go, Google Cloud Go SDK
- **Auth/Security:** OIDC/OAuth2 (go-oidc), JWT, Argon2id, OPA (RBAC/ABAC), Vault/AWS Secrets Manager
- **Observability:** Zap or Zerolog (logging), Prometheus (metrics), OpenTelemetry (tracing), Sentry (error tracking)
- **Background Jobs:** Asynq (Redis-backed), Cron
- **Testing:** Go built-in testing, Testcontainers-go, Mockery
- **CI/CD:** Docker, Kubernetes, GitHub Actions, Helm
- **Config:** Viper
- **Migrations:** golang-migrate
- **Dependency Injection:** Wire
- **API Docs:** OpenAPI/Swagger

## Project Structure

- `/cmd` – Service entrypoints
- `/internal` – Business logic, domain, adapters (no cross-service imports)
- `/pkg` – Reusable libraries (safe for external use)
- `/api` – OpenAPI specs, API contracts
- `/migrations` – DB migrations
- `/test` – Integration/unit tests
- `/deploy` – K8s, Docker, Helm charts
- `/enterprise` – Modular, production-grade enterprise features (see enterprise/README.md)

## Coding Rules (Strict)

- **No placeholders, no dummy code, no mixed prod/non-prod content.**
- **All code must be linter-clean, type-safe, and pass static analysis.**
- **No commented-out code, no TODOs, no "fix later" notes.**
- **No hardcoded secrets, no insecure defaults, no panics.**
- **All error handling must be robust, user-friendly, and never leak sensitive info.**
- **All code must be secure by default.**
- **All dependencies must be up-to-date, minimal, and explicitly required.**
- **All code must be cloud-native, container-ready, and CI/CD friendly.**
- **All architectural decisions must be explicit and justified in code comments.**
- **No "misc", "tmp", or catch-all folders.**
- **No "example", "sample", or "test" code outside of dedicated test directories.**
- **All code must be easily testable and ready for CI/CD integration.**
- **All code, comments, and documentation must be written for expert-level developers.**
- **All code must be compatible with the latest stable versions of all relevant tools and languages.**
- **All code must be accessible and maintainable by any senior engineer without additional context.**
- **If a convention or best practice is violated, document the reason in code comments.**

## Development Process

- All code must be reviewed for real-world SaaS readiness before merge.
- No code is merged without passing all linters, static analysis, and tests.
- All new features and modules must be production-grade, secure, and ready for SaaS deployment.
- All code must be modular, DRY, and reflect real-world microservice boundaries.
- No mixing of prod and non-prod code in the same directory.
- All code must be cloud-agnostic and ready for multi-cloud, multi-region, and multi-tenant deployment.
- All architectural decisions must be documented in code comments and/or README files.

---

**This repository is for backend only. No frontend code, no UI, no non-backend logic.**

---

## Admin Backend Architecture

- **Admin API:** All admin endpoints are versioned, strictly separated from tenant/user APIs, and protected by RBAC/ABAC. No admin logic is exposed to tenants or regular users.
- **Admin Business Logic:** Located in `/internal/admin` and `/enterprise/admin` for superuser operations, tenant/org/project/region management, system configuration, audit, and compliance. No mixing of admin and tenant logic.
- **Security:** All admin endpoints require elevated authentication and authorization. All actions are auditable. No hardcoded secrets, no insecure defaults, no panics.
- **Boundaries:** No admin code or endpoints in tenant/user modules. No shared handlers or business logic between admin and tenant APIs. All admin code is production-grade, modular, and ready for SaaS deployment.
- **Review:** All admin code must be reviewed for real-world SaaS readiness, security, and compliance before merge.

## Security Features & Enforcement

- **Authentication:** All endpoints require strong authentication (OIDC/OAuth2, JWT, Argon2id for passwords). No anonymous access. MFA enforced for admin and sensitive operations.
- **Authorization:** Strict RBAC/ABAC enforced at API and business logic layers. OPA used for policy evaluation. No privilege escalation, no insecure defaults.
- **Secrets Management:** All secrets managed via Vault or AWS Secrets Manager. No hardcoded secrets, no secrets in code or config files. All secrets are rotated and auditable.
- **Audit & Compliance:** All sensitive actions are logged with full context. Audit logs are immutable, tamper-evident, and exportable for compliance (SOC2, ISO, etc.).
- **Secure Defaults:** All services start with least privilege, secure headers, CORS, and rate limiting. No panics, no silent failures, no insecure fallbacks.
- **Error Handling:** All errors are user-friendly, never leak sensitive info, and are logged for ops. No stack traces or internal details in API responses.
- **Dependencies:** All dependencies are minimal, up-to-date, and scanned for vulnerabilities. No legacy or unmaintained packages.
- **Network:** All traffic is encrypted in transit (TLS 1.3+). No plaintext protocols. All endpoints are protected by API gateway and WAF.
- **Review:** All code is reviewed for security, compliance, and SaaS readiness before merge. No exceptions.

## SaaS Product Vision & Features

**Subinc Cloud Management Platform**

A multi-tenant SaaS for non-engineers to manage, optimize, and govern AWS, Azure, and GCP environments. All features are production-grade, secure, and ready for enterprise scale.

### Core Features
- **Multi-Cloud Cost Tracking:** Unified dashboard for AWS, Azure, GCP spend, trends, and forecasts per tenant, org, project, and user.
- **Provisioning & Automation:** Self-service resource provisioning, IaC integration, and lifecycle management with guardrails.
- **Architecture Documentation:** Auto-generate and manage architecture docs, versioned and exportable.
- **Live Diagrams:** Visualize cloud resources, service-to-service connections, and network topology in real time.
- **Optimization:** Cost, performance, and resource optimization recommendations with actionable insights.
- **Security & Compliance:** Continuous security posture monitoring, compliance checks (SOC2, ISO, CIS, HIPAA), and automated remediation.
- **Audit & Activity Logging:** Immutable, exportable audit logs for all actions, with full context and compliance support.
- **Payments & Billing:** Integrated billing, invoicing, and payment processing per tenant/org/project. Usage-based and subscription models supported.
- **Access & User Management:** Fine-grained RBAC/ABAC, SSO, SCIM, and delegated administration. Tenant isolation enforced at all layers.
- **Visualization & Reporting:** Customizable dashboards, reports, and exportable analytics for all features.

### Unique Requirements
- **No-Engineer UX:** All features accessible via API and admin UI (UI not in this repo), with clear docs and automation hooks.
- **Cloud-Native & Extensible:** Modular, API-first, and ready for integration with 3rd-party tools and workflows.
- **Enterprise-Ready:** Multi-tenant, multi-region, and multi-cloud by design. All code, infra, and processes are SaaS production-grade.
- **AI-Driven Intelligence:** Automated recommendations, anomaly detection, and insights for cost, security, compliance, and architecture—powered by AI/ML models for continuous optimization and proactive risk mitigation.

--- 