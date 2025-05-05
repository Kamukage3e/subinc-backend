# Backend Tasklist – Subinc Cost Management Microservice

- [ ] Initialize Go module, .gitignore, and CI/CD config
- [ ] Enforce linter, static analysis, and security scanning in CI
- [ ] Set up Dockerfile, docker-compose, and Helm charts for local/dev/prod

## Core Service Structure
- [ ] Create `/cmd` entrypoint (main.go, config, graceful shutdown)
- [ ] Scaffold `/internal` for business logic, adapters, domain
- [ ] Scaffold `/pkg` for reusable libraries/utilities
- [ ] Scaffold `/api` for OpenAPI specs and API contracts
- [ ] Scaffold `/migrations` for DB migrations (golang-migrate)
- [ ] Scaffold `/test` for integration/unit tests
- [ ] Scaffold `/deploy` for K8s, Docker, Helm
- [ ] Scaffold `/enterprise` for modular enterprise features

## Enterprise Modules
- [ ] Implement `/enterprise/auth` (SSO, SAML, OIDC, RBAC/ABAC)
- [ ] Implement `/enterprise/billing` (multi-tenant billing, invoicing, cost centers)
- [ ] Implement `/enterprise/compliance` (SOC2, ISO, audit, export)
- [ ] Implement `/enterprise/integrations` (Okta, Workday, Slack, Teams, etc.)
- [ ] Implement `/enterprise/notifications` (email, SMS, push, cloud events)
- [ ] Implement `/enterprise/audit` (immutable, tamper-evident logs)
- [ ] Implement `/enterprise/user-management` (SCIM, org/user provisioning)
- [ ] Implement `/enterprise/api` (enterprise-only endpoints)
- [ ] Implement `/enterprise/organization` (multi-org, org policies/settings)
- [ ] Implement `/enterprise/project` (project isolation, grouping, policies)
- [ ] Implement `/enterprise/region` (multi-region, failover, geo-redundancy)
- [ ] Implement `/enterprise/admin` (superuser ops, tenant/org/project/region management, system config)

## Database Layer
- [ ] Design multi-tenant schema (org, project, user, region, resource, cost, audit, etc.)
- [ ] Implement GORM models, migrations, and raw SQL for perf-critical paths
- [ ] Integrate Redis for caching, rate limiting, and background jobs

## API Layer
- [ ] Implement RESTful endpoints for all core and enterprise modules
- [ ] Version all APIs, separate admin endpoints, enforce OpenAPI contract
- [ ] Add middleware for logging, metrics, CORS, secure headers, rate limiting

## Auth & Security
- [ ] Integrate OIDC/OAuth2, JWT, Argon2id, MFA
- [ ] Enforce RBAC/ABAC with OPA
- [ ] Integrate Vault/AWS Secrets Manager for secrets
- [ ] Implement secure error handling, no sensitive info leaks
- [ ] Enforce TLS 1.3+, API gateway, WAF

## Observability
- [ ] Integrate Zap/Zerolog for structured logging
- [ ] Integrate Prometheus for metrics
- [ ] Integrate OpenTelemetry for tracing
- [ ] Integrate Sentry for error tracking

## Background Jobs & Scheduling
- [ ] Integrate Asynq for background jobs (cost sync, notifications, audits)
- [ ] Implement cron jobs for scheduled tasks (billing, compliance checks, etc.)

## Testing
- [ ] Write unit tests for all business logic
- [ ] Write integration tests using Testcontainers-go
- [ ] Mock external dependencies with Mockery

## Documentation
- [ ] Maintain up-to-date README and module docs
- [ ] Document all architectural decisions in code comments
- [ ] Maintain OpenAPI/Swagger docs for all APIs

## Review & Enforcement
- [ ] Enforce all coding, security, and architectural rules in PR review
- [ ] No code merged without passing all checks and review 