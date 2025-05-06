# Subinc Cost Management API Integration Guide

## General API Information

- **Base URL:** `/api` (see OpenAPI YAML for versioned prefixes)
- **OpenAPI Spec:** `api/openapi.yaml` (OpenAPI 3.1, always up-to-date)
- **Authentication:**
  - JWT Bearer tokens for all client and admin endpoints
  - Obtain via `/users/login` (client) or admin SSO
  - All endpoints require valid JWT unless explicitly marked public
- **RBAC/ABAC:**
  - Role-based and attribute-based access enforced on all sensitive endpoints
  - Claims in JWT: `sub`, `tenant_id`, `roles`, `attributes`
  - Admin endpoints require `admin` or higher role
- **Error Handling:**
  - All errors are JSON: `{ "error": "message" }`
  - 4xx for client errors, 5xx for server errors
  - No stack traces or sensitive info ever leaked
- **Versioning:**
  - Versioned via URL prefix (e.g. `/api/v1`)
  - Breaking changes require new version
- **Rate Limiting:**
  - Enforced globally and per-user (configurable)
  - 429 returned on limit exceeded
- **Idempotency:**
  - All POST/PUT endpoints are idempotent if `Idempotency-Key` header is provided
- **Pagination & Filtering:**
  - Standard `limit` and `offset` query params
  - Filtering via query params (see OpenAPI for each endpoint)
- **Webhooks:**
  - Register via `/webhooks` (POST)
  - All webhook events are signed (HMAC-SHA256, secret per webhook)
  - Retry with exponential backoff on failure
- **Async Jobs:**
  - All async jobs (provisioning, imports, etc.) are enqueued and tracked via `/provisioning` and `/cost/imports`
  - Job status endpoints return real-time state
- **Monitoring:**
  - Prometheus metrics at `/metrics`
  - Health checks at `/health` and `/system/health/deep`

## Deep Integration Details

### Auth Flows
- **User Login:**
  - `POST /users/login` with `{ username, password }` returns `{ token }`
  - Use `Authorization: Bearer <token>` for all subsequent requests
- **Admin Login:**
  - SSO or admin login endpoint (see `/admin`)
  - JWT includes elevated roles
- **Token Expiry:**
  - Tokens expire after 24h (configurable)
  - Use refresh flow or re-login as needed

### Request/Response Patterns
- **All requests/response bodies are JSON**
- **Timestamps:** ISO8601 UTC strings
- **IDs:** Always string, never integer (UUID or hashid)
- **Errors:** Always `{ "error": "message" }`
- **Success:** 2xx with JSON body or 204 No Content

### Pagination, Filtering, Sorting
- `limit` (default 100, max 1000), `offset` (default 0)
- Filtering params are endpoint-specific (see OpenAPI)
- Sorting via `sort_by` and `sort_dir` if supported

### Webhooks
- Register: `POST /webhooks` with `{ url, events }`
- Receive: POST requests with event payload, signed with HMAC
- Validate signature using your webhook secret
- Respond 2xx to acknowledge, non-2xx triggers retry

### Idempotency
- Send `Idempotency-Key` header for all POST/PUT requests to guarantee idempotent processing
- Duplicate requests with same key will not create duplicates

### Async Jobs & Background Processing
- **Provisioning:**
  - `POST /provisioning/terraform` to enqueue
  - Track via `/provisioning/terraform/{id}`
- **Cost Imports:**
  - `POST /cost/imports` to start
  - Track via `/cost/imports/{id}`
- **Job status:**
  - All job status endpoints return `{ status, ... }` and progress fields
- **Job queue is Redis-backed, monitored, and auto-retries on failure**

### OpenAPI Codegen/SDKs
- Use `api/openapi.yaml` for generating client SDKs (e.g. with openapi-generator, Swagger Codegen, or go-swagger)
- All schemas, request/response types, and error models are up-to-date
- No undocumented endpoints

### Security & Best Practices
- Always use HTTPS
- Never log or expose JWTs, secrets, or sensitive data
- Rotate secrets and API keys regularly
- Use RBAC/ABAC claims for all access control
- Monitor `/metrics` and `/health` for service health
- Use idempotency keys for all non-GET requests
- Validate all webhook signatures
- Handle 429 (rate limit) and 401/403 (auth) errors gracefully

### Real-World SaaS Integration Tips
- Use service accounts for automation, not user tokens
- Use pagination for all list endpoints
- Use webhooks for real-time event-driven workflows
- Monitor job status endpoints for async operations
- Use OpenAPI spec for CI/CD contract tests
- All endpoints are production-grade, no placeholders, no dummy data

---

**For full endpoint and schema details, see `api/openapi.yaml`. All integration points are real, production-ready, and SaaS-grade.** 