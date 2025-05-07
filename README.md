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

## SaaS Product Features: Implementation Status

| Feature                        | User | Admin | Status         |
|--------------------------------|------|-------|---------------|
| Multi-Cloud Cost Tracking       | ✔️   | ✔️    | Implemented   |
| Provisioning & Automation       | ✔️   | ✔️    | Implemented   |
| Architecture Docs/Live Diagrams | ✔️   | ✔️    | Implemented   |
| Optimization Recommendations    | ✔️   | ✔️    | Implemented   |
| Security & Compliance           | ✔️   | ✔️    | Implemented   |
| Audit & Activity Logging        | ✔️   | ✔️    | Implemented   |
| Payments & Billing              | ✔️   | ✔️    | Implemented   |
| Access & User Management        | ✔️   | ✔️    | Implemented   |
| Visualization & Reporting       | ❌   | ❌    | Not implemented |
| AI-Driven Intelligence          | ✔️   | ✔️    | Implemented (anomaly detection, explainable recommendations) |
| Notifications                   | ✔️   | ✔️    | Implemented   |

---

### Feature Notes
- **Architecture Documentation & Live Diagrams:** Fully implemented. Endpoints for auto-generation, versioning, export, and real-time visualization of cloud resources/topology are available under `/architecture`. The backend stores and returns the full ArchitectureGraph (nodes + edges) for every doc, supporting all AWS services discovered by the backend scanner. All endpoints are production-ready, RBAC/ABAC-protected, and SaaS-grade. See OpenAPI spec for details.
- **Provisioning & Automation:** Fully implemented. Endpoints for resource provisioning, automation, and guardrails are available and production-grade.
- **Optimization Recommendations:** Fully implemented. API, service, and OpenAPI spec are present. Engine integration (OpenAI, AWS, Azure, GCP) is production-ready. The backend supports real-world SaaS credential onboarding and multi-cloud optimization.
- **AI-Driven Intelligence:** Anomaly detection and explainable recommendations are present. The system is extensible for future AI/ML-powered insights for cost/security/compliance/architecture.
- **Security & Compliance:** RBAC/ABAC, OPA, audit logging, and MFA are present. All endpoints are production-grade and SaaS-ready. Compliance frameworks (SOC2, ISO, CIS, HIPAA) can be added as needed.
- **Access & User Management:** RBAC/ABAC, delegated admin, and tenant isolation are present. SSO and SCIM are referenced and extensible.
- **Audit & Activity Logging:** Full CRUD, search, and export for audit logs, with robust error handling and RBAC.
- **Notifications:** Real notification system (email, webhook, etc.) with admin endpoints, persistence, and delivery logic.
- **Budgets, Refunds, Invoices, Credits, Payments, Subscriptions, Webhook Events, Invoice Adjustments:** All implemented, production-grade, and ready for SaaS deployment.
- **Enterprise Features:** `/enterprise` directory contains only production-grade, modular features.
- **Future AWS Service Enhancements:**
  The following AWS services are high-priority for future enhancement of the cost microservice, due to their enterprise value, complexity, or cost impact:
  - AWS Organizations: For consolidated billing, cross-account cost analysis, and enterprise RBAC/ABAC.
  - AWS Control Tower: For multi-account governance and landing zone automation.
  - AWS Savings Plans & Reserved Instances: For advanced cost optimization and commitment management.
  - AWS Marketplace: For third-party SaaS spend tracking and cost allocation.
  - AWS Service Catalog: For managed product portfolios and cost controls.
  - AWS Outposts & Local Zones: For hybrid cloud and edge cost visibility.
  - AWS Data Exchange: For external data cost tracking and compliance.
  - AWS License Manager: For software license cost and compliance management.
  - AWS Budgets & Cost Anomaly Detection: For proactive cost controls and anomaly alerting.
  - AWS Billing Conductor: For custom billing and chargeback models.
  - AWS CloudEndure, DMS, and Migration Hub: For migration cost tracking and reporting.
  - AWS AppConfig, CodeArtifact, and AppRunner: For modern app delivery and cost visibility.
  - AWS IoT, Greengrass, and RoboMaker: For IoT and robotics cost management at scale.
  - AWS Managed Blockchain: For distributed ledger cost and usage tracking.
  - AWS Ground Station: For satellite data cost management.
  - AWS Quantum Technologies: For future-proofing cost analytics.
  These services are critical for SaaS customers with complex, multi-cloud, or regulated environments. Roadmap prioritization should be based on customer demand and cost impact.

---

**This README reflects the current production-grade, real-world SaaS backend implementation. All features listed as implemented are present in the codebase and ready for deployment.**

---

## Payment Provider Disabling (Local/Dev/Test)

Set `PAYMENTS_DISABLED=true` in your environment to disable all payment providers (Stripe, PayPal, Google Pay, Apple Pay). When disabled:

- No real payment API calls are made
- No provider credentials are required
- All provider constructors use dummy keys:
  - Stripe: `dummy-stripe-key`
  - PayPal: `dummy-paypal-client-id`, `dummy-paypal-client-secret`
  - Google Pay: `dummy-googlepay-merchant-id`, `dummy-googlepay-api-key`
  - Apple Pay: `dummy-applepay-merchant-id`, `dummy-applepay-api-key`
- All tokenization methods return static dummy tokens/metadata
- No panics or errors if real env vars are missing

**Production:**
- Leave `PAYMENTS_DISABLED` unset or set to `false` to enable real payment processing.
- All required provider env vars must be set for production.

This feature is for local/dev/test only. Never use dummy mode in production.

## Middleware

- **CORS**: Applied globally for all routes.
- **Security Headers**: Strict HTTP security headers (helmet) enforced globally for all routes.
- **Request Logging**: Structured, audit-grade logging for all requests, including admin API audit logs.
- **Distributed Rate Limiting**: Redis-backed, production-grade rate limiting applied globally to protect against abuse and DoS.

All middleware is enforced for every route and is production-grade, with no exceptions or bypasses. 