# SubInc Frontend Developer Documentation

## 1. Overview & Tech Stack

SubInc is a multi-tenant SaaS billing platform. The backend exposes a robust REST API with RBAC, JWT, and ID hashing. All frontend apps must be production-grade, secure, and cloud-native.

**Recommended Tech Stack:**
- React (Next.js 14 App Router, Vite, or similar)
- TypeScript (strict mode)
- Tailwind CSS (with shadcn/ui, Radix UI, Tailwind Aria)
- Zod for validation
- TanStack Query for data fetching
- Viem/Wagmi for web3 (if needed)
- Use Suspense, RSC, and SSR for performance

## 2. API Endpoint Layout

**API Base Path:** `/api/v1/`

### User-Facing (Customer Portal)
- `/billing-management/payments/customer-portal` (GET)
- `/billing-management/payments/customer-portal/subscriptions` (GET)
- `/billing-management/payments/customer-portal/payment-methods` (GET)
- `/billing-management/payments/customer-portal/invoices` (GET)
- `/billing-management/payments/customer-portal/usage` (GET)

**Query Params:**
- `account_id` (required)
- `return_url` (optional)

**Headers:**
- `Authorization: Bearer <JWT>`
- `X-Tenant-ID: <tenant_id>`

**Response:**
```json
{ "url": "https://billing.stripe.com/session/abc..." }
```

### Admin-Facing (Billing Management)
- `/billing-management/invoices` (CRUD, PDF download)
- `/billing-management/reports/*` (revenue, AR, churn)
- `/billing-management/dunning/*` (config, dashboard, retry)
- `/billing-management/plugins/*` (list, configure, disable)
- `/billing-management/webhook-events` (CRUD)
- `/billing-management/tenant-currency` (GET/POST)
- `/billing-management/webhook-subscriptions` (CRUD, logs, test)
- `/billing-management/accounts/invoice-preview` (GET)
- `/billing-management/payments/*` (full payment, refund, dispute, method CRUD)

### User/Org/Tenant Management
- `/users` (CRUD, profile, settings, org/project membership)
- `/tenant-management/tenants` (CRUD, settings, status, migration)

### Auth & Security
- `/auth/login` (POST)
- `/auth/logout` (POST)
- `/auth/refresh` (POST)
- `/auth/password-reset` (POST/PUT)
- `/users/:id/mfa` (enable/disable)
- `/users/:id/api-keys` (CRUD)

## 3. Authentication, Session, and Headers
- All endpoints require JWT in `Authorization` header.
- Use `X-Tenant-ID` for multi-tenant context.
- Session tokens are short-lived; use refresh flow.
- MFA endpoints for user security.

## 4. Request/Response & ID Hashing
- All IDs in requests/responses are HMAC-SHA256 hashed (see README).
- Never parse or generate IDs client-side; always use as-is.
- All responses are JSON, errors are always `{ "error": "..." }`.
- Pagination: `page`, `page_size` query params; responses include `total`.

## 5. Customer Portal Integration
- Use `/billing-management/payments/customer-portal` endpoints to redirect users to Stripe.
- See `docs/customer-portal-integration.md` for React example.
- RBAC: user must have `payment-method:read` permission.
- All sensitive actions (payment, subscription) handled by Stripe.

## 6. Example Flows

### Login
```ts
POST /api/v1/auth/login
{ email, password }
-> { session_token, refresh_token, expires_at }
```

### Open Customer Portal
```ts
GET /api/v1/billing-management/payments/customer-portal?account_id=...&return_url=...
Headers: Authorization, X-Tenant-ID
-> { url }
window.location.href = url
```

### List Invoices (Admin)
```ts
GET /api/v1/billing-management/invoices?page=1&page_size=20
Headers: Authorization, X-Tenant-ID
-> { invoices: Invoice[], total: number }
```

### Update User Profile
```ts
PUT /api/v1/users/:id
Headers: Authorization, X-Tenant-ID
Body: { ...profile fields... }
-> { ...updated user... }
```

## 7. UI/UX: Who, When, Where
- **User Portal:**
  - Who: End users (customers)
  - Where: `/account/billing`, `/settings/billing` in your app
  - When: After login, or from account/settings menu
  - How: Button/link to "Manage Billing" (redirects to Stripe portal)
- **Admin Panel:**
  - Who: Admins, support, finance
  - Where: `/admin/billing`, `/admin/reports`, `/admin/dunning`
  - When: After admin login, or from dashboard
  - How: Full CRUD UI for invoices, payments, dunning, plugins, etc.

## 8. Security & Compliance
- All API access is RBAC-protected; never expose admin endpoints to users.
- All IDs are hashed; never display raw IDs.
- All payment data handled by Stripe; PCI compliance is Stripe's responsibility.
- All actions are audit-logged.
- Use HTTPS for all frontend/backend communication.

## 9. Data Model Summary
- **User:** `{ id, email, status, created_at, updated_at }`
- **UserProfile:** `{ user_id, full_name, avatar_url, bio, ... }`
- **Tenant:** `{ id, name, status, settings, created_at, updated_at }`
- **Account:** `{ id, tenant_id, email, status, currency, ... }`
- **Invoice:** `{ id, account_id, amount, currency, status, due_date, ... }`
- **Payment:** `{ id, invoice_id, amount, currency, status, method, ... }`
- **PaymentMethod:** `{ id, account_id, type, provider, last4, exp_month, exp_year, ... }`
- **APIKey:** `{ id, tenant_id, key, status, ... }`
- **Plugin:** `{ id, tenant_id, name, type, config, status, ... }`
- **WebhookSubscription:** `{ id, tenant_id, url, event_types, ... }`

## 10. References
- [Swagger UI](http://localhost:8080/docs) (run backend locally)
- [OpenAPI Spec](http://localhost:8080/swagger.yaml)
- [Customer Portal Guide](docs/customer-portal-integration.md)

---

**For any questions, contact the backend team or consult the OpenAPI spec. All frontend code must be reviewed for security, RBAC, and ID handling before deployment.**

---

# Section Breakdown: What, How, When, Where, Who, API

## 1. User Authentication & Session

### What
- Login, logout, password reset, session refresh, MFA
- User profile and settings

### How
- Next.js RSC for login page, protected routes
- JWT stored in httpOnly cookie
- Zod for form validation
- TanStack Query for user/session fetch

### When
- **MVP:** Login/logout, session refresh, password reset
- **Post-MVP:** MFA, device/session management

### Where
- `/login`, `/logout`, `/reset-password`, `/profile`, `/settings`

### Who
- Frontend team (auth specialist)
- Backend team for endpoint support

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/auth/login` | POST | `{ email, password }` | `{ session_token, refresh_token, expires_at }` | - | public |
| `/auth/logout` | POST | - | 204 | `Authorization` | user |
| `/auth/refresh` | POST | `{ refresh_token }` | `{ session_token, expires_at }` | - | user |
| `/auth/password-reset` | POST | `{ email }` | 201 | - | public |
| `/auth/password-reset` | PUT | `{ token, password }` | 204 | - | public |
| `/users/:id/mfa` | POST/DELETE | - | 204 | `Authorization` | user |

### Endpoint Details: User Authentication & Session

#### `/auth/login` (POST)
- **Request:**
```json
{
  "email": "string (required, valid email)",
  "password": "string (required, min 8 chars)"
}
```
- **Response (200):**
```json
{
  "session_token": "string (JWT, required)",
  "refresh_token": "string (JWT, required)",
  "expires_at": "string (ISO8601, required)"
}
```
- **Response (Error):**
```json
{
  "error": "Invalid credentials",
  "code": "AUTH_REQUIRED"
}
```
- **Headers:** None required in request. Response sets `Set-Cookie` if using httpOnly cookies.
- **RBAC:** Public (no auth required)

---

#### `/auth/logout` (POST)
- **Request:** None
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "Not authenticated",
  "code": "AUTH_REQUIRED"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
- **RBAC:** User (must be authenticated)

---

#### `/auth/refresh` (POST)
- **Request:**
```json
{
  "refresh_token": "string (required, valid JWT)"
}
```
- **Response (200):**
```json
{
  "session_token": "string (JWT, required)",
  "expires_at": "string (ISO8601, required)"
}
```
- **Response (Error):**
```json
{
  "error": "Invalid refresh token",
  "code": "AUTH_REQUIRED"
}
```
- **Headers:** None required in request. Response sets `Set-Cookie` if using httpOnly cookies.
- **RBAC:** User (must be authenticated)

---

#### `/auth/password-reset` (POST)
- **Request:**
```json
{
  "email": "string (required, valid email)"
}
```
- **Response (201):**
```json
{
  "message": "Password reset email sent"
}
```
- **Response (Error):**
```json
{
  "error": "Email not found",
  "code": "NOT_FOUND"
}
```
- **Headers:** None
- **RBAC:** Public

---

#### `/auth/password-reset` (PUT)
- **Request:**
```json
{
  "token": "string (required, valid reset token)",
  "password": "string (required, min 8 chars)"
}
```
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "Invalid or expired token",
  "code": "FORBIDDEN"
}
```
- **Headers:** None
- **RBAC:** Public

---

#### `/users/:id/mfa` (POST/DELETE)
- **Request:** None
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "MFA not enabled for tenant",
  "code": "FORBIDDEN"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
- **RBAC:** User (must be authenticated)

---

## 2. User Portal (Billing/Subscription)

### What
- Self-service billing portal (Stripe)
- View/manage subscriptions, payment methods, invoices, usage

### How
- Button/link in app opens Stripe portal via backend endpoint
- Minimal UI: "Manage Billing", "View Invoices", etc.
- RBAC: `payment-method:read` required

### When
- **MVP:** Portal redirect, invoice list
- **Post-MVP:** In-app usage dashboard, custom invoice view

### Where
- `/account/billing`, `/settings/billing`

### Who
- Frontend team (billing integration)
- Backend team (Stripe integration)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/payments/customer-portal` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |
| `/billing-management/payments/customer-portal/subscriptions` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |
| `/billing-management/payments/customer-portal/payment-methods` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |
| `/billing-management/payments/customer-portal/invoices` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |
| `/billing-management/payments/customer-portal/usage` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |

### Endpoint Details: User Portal (Billing/Subscription)

#### `/billing-management/payments/customer-portal` (GET)
- **Request (Query Params):**
  - `account_id`: string (required, hashed ID of billing account)
  - `return_url`: string (optional, URL to return after portal)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "url": "string (required, Stripe portal session URL)"
}
```
- **Response (Error):**
```json
{
  "error": "Customer not found in Stripe",
  "code": "NOT_FOUND"
}
```
- **RBAC:** User (must have `payment-method:read` permission)

---

#### `/billing-management/payments/customer-portal/subscriptions` (GET)
- **Request (Query Params):**
  - `account_id`: string (required)
  - `return_url`: string (optional)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "url": "string (required, Stripe portal session URL for subscriptions section)"
}
```
- **Response (Error):**
```json
{
  "error": "Customer not found in Stripe",
  "code": "NOT_FOUND"
}
```
- **RBAC:** User (must have `payment-method:read` permission)

---

#### `/billing-management/payments/customer-portal/payment-methods` (GET)
- **Request (Query Params):**
  - `account_id`: string (required)
  - `return_url`: string (optional)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "url": "string (required, Stripe portal session URL for payment methods section)"
}
```
- **Response (Error):**
```json
{
  "error": "Customer not found in Stripe",
  "code": "NOT_FOUND"
}
```
- **RBAC:** User (must have `payment-method:read` permission)

---

#### `/billing-management/payments/customer-portal/invoices` (GET)
- **Request (Query Params):**
  - `account_id`: string (required)
  - `return_url`: string (optional)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "url": "string (required, Stripe portal session URL for invoices section)"
}
```
- **Response (Error):**
```json
{
  "error": "Customer not found in Stripe",
  "code": "NOT_FOUND"
}
```
- **RBAC:** User (must have `payment-method:read` permission)

---

#### `/billing-management/payments/customer-portal/usage` (GET)
- **Request (Query Params):**
  - `account_id`: string (required)
  - `return_url`: string (optional)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "url": "string (required, Stripe portal session URL for usage section)"
}
```
- **Response (Error):**
```json
{
  "error": "Customer not found in Stripe",
  "code": "NOT_FOUND"
}
```
- **RBAC:** User (must have `payment-method:read` permission)

---

## 3. Admin Panel (Billing Management)

### What
- Full CRUD for invoices, payments, dunning, plugins, reports
- Manual adjustments, PDF export, AR/churn/revenue reports

### How
- Next.js RSC for admin dashboard
- TanStack Query for data
- RBAC: admin roles only

### When
- **MVP:** Invoice/payment CRUD, dunning dashboard, reports
- **Post-MVP:** Plugin config, webhook logs, advanced analytics

### Where
- `/admin/billing`, `/admin/invoices`, `/admin/reports`, `/admin/dunning`, `/admin/plugins`

### Who
- Frontend team (admin specialist)
- Backend team (billing, reporting)

### API (sample)
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/invoices` | GET/POST | `{ ... }` | `{ invoices: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/invoices/:id` | GET/PUT/DELETE | `{ ... }` | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/reports/revenue` | GET | - | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/dunning/dashboard` | GET | - | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |

### Endpoint Details: Admin Panel (Billing Management)

#### `/billing-management/invoices` (GET)
- **Request (Query Params):**
  - `page`: integer (optional, default 1)
  - `page_size`: integer (optional, default 20)
  - `status`: string (optional, filter by invoice status)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "invoices": [
    {
      "id": "string (hashed)",
      "account_id": "string (hashed)",
      "amount": 123.45,
      "currency": "USD",
      "status": "open|paid|overdue|draft",
      "due_date": "string (ISO8601)",
      "created_at": "string (ISO8601)",
      "updated_at": "string (ISO8601)"
    }
  ],
  "total": 42
}
```
- **Response (Error):**
```json
{
  "error": "Failed to list invoices",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `invoice:read` permission)

---

#### `/billing-management/invoices` (POST)
- **Request:**
```json
{
  "account_id": "string (hashed, required)",
  "amount": 123.45,
  "currency": "USD",
  "due_date": "string (ISO8601, required)",
  "line_items": [
    { "description": "string", "amount": 100.00, "quantity": 1 }
  ]
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (201):**
```json
{
  "id": "string (hashed)",
  "status": "draft|open|paid|overdue",
  "created_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR"
}
```
- **RBAC:** Admin (must have `invoice:create` permission)

---

#### `/billing-management/invoices/:id` (GET)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "account_id": "string (hashed)",
  "amount": 123.45,
  "currency": "USD",
  "status": "open|paid|overdue|draft",
  "due_date": "string (ISO8601)",
  "line_items": [
    { "description": "string", "amount": 100.00, "quantity": 1 }
  ],
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Invoice not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `invoice:read` permission)

---

#### `/billing-management/invoices/:id` (PUT)
- **Request:**
```json
{
  "amount": 123.45,
  "currency": "USD",
  "due_date": "string (ISO8601)",
  "status": "open|paid|overdue|draft",
  "line_items": [
    { "description": "string", "amount": 100.00, "quantity": 1 }
  ]
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "status": "open|paid|overdue|draft",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR"
}
```
- **RBAC:** Admin (must have `invoice:update` permission)

---

#### `/billing-management/invoices/:id` (DELETE)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "Invoice not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `invoice:delete` permission)

---

#### `/billing-management/invoices/:id/pdf` (GET)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):** PDF file (Content-Type: application/pdf)
- **Response (Error):**
```json
{
  "error": "Invoice not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `invoice:read` permission)

---

#### `/billing-management/reports/revenue` (GET)
- **Request (Query Params):**
  - `start_date`: string (optional, ISO8601)
  - `end_date`: string (optional, ISO8601)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "total_revenue": 12345.67,
  "currency": "USD",
  "period": {
    "start": "string (ISO8601)",
    "end": "string (ISO8601)"
  },
  "daily": [
    { "date": "string (ISO8601)", "amount": 123.45 }
  ]
}
```
- **Response (Error):**
```json
{
  "error": "Failed to generate report",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `report:read` permission)

---

#### `/billing-management/dunning/dashboard` (GET)
- **Request:** None
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "active_count": 5,
  "completed_count": 10,
  "failed_count": 2,
  "paused_count": 1,
  "total_amount_in_dunning": 1234.56,
  "success_rate": 0.95,
  "recent_events": [
    {
      "id": "string (hashed)",
      "invoice_id": "string (hashed)",
      "event_type": "payment_failed|retry|success|canceled",
      "status": "pending|processed|failed",
      "created_at": "string (ISO8601)"
    }
  ],
  "generated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Failed to load dunning dashboard",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `dunning:read` permission)

---

## 4. Organization/Tenant Management

### What
- Tenant CRUD, settings, status, migration
- Org membership, invites, user roles

### How
- Next.js RSC for org/tenant screens
- Zod for validation
- RBAC: admin/owner only

### When
- **MVP:** Tenant CRUD, user/org management
- **Post-MVP:** Migration, advanced settings

### Where
- `/admin/tenants`, `/admin/orgs`, `/admin/users`

### Who
- Frontend team (org/tenant specialist)
- Backend team (tenant management)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/tenant-management/tenants` | GET/POST | `{ ... }` | `{ tenants: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/tenant-management/tenants/:id` | GET/PUT/DELETE | `{ ... }` | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |
| `/users` | GET/POST | `{ ... }` | `{ users: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/users/:id` | GET/PUT/DELETE | `{ ... }` | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |

## 5. Security & API Key Management

### What
- MFA, device/session management, API key CRUD

### How
- Next.js RSC for security screens
- RBAC: user/admin

### When
- **MVP:** API key CRUD, MFA enable/disable
- **Post-MVP:** Device/session management

### Where
- `/settings/security`, `/settings/api-keys`

### Who
- Frontend team (security specialist)
- Backend team (security management)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/users/:id/api-keys` | GET/POST/DELETE | `{ ... }` | `{ api_keys: [], total }` | `Authorization`, `X-Tenant-ID` | user |
| `/users/:id/mfa` | POST/DELETE | - | 204 | `Authorization`, `X-Tenant-ID` | user |

## 6. Notifications & Webhooks

### What
- Webhook subscription CRUD, delivery logs, test delivery
- Notification config (email, Slack, etc)

### How
- Next.js RSC for webhook/notification screens
- RBAC: admin only

### When
- **MVP:** Webhook CRUD, logs
- **Post-MVP:** Notification config UI

### Where
- `/admin/webhooks`, `/admin/notifications`

### Who
- Frontend team (integration specialist)
- Backend team (webhook/notification)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/webhook-subscriptions` | GET/POST | `{ ... }` | `{ webhook_subscriptions: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/webhook-subscriptions/:id` | GET/PUT/DELETE | `{ ... }` | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/webhook-subscriptions/:id/logs` | GET | - | `{ logs: [] }` | `Authorization`, `X-Tenant-ID` | admin |

## 7. Usage Dashboard

### What
- In-app usage metrics, API usage, billing estimates

### How
- Next.js RSC for dashboard
- TanStack Query for usage data
- RBAC: user/admin

### When
- **Post-MVP:** Usage dashboard

### Where
- `/account/usage`, `/admin/usage`

### Who
- Frontend team (dashboard specialist)
- Backend team (usage metering)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/payments/customer-portal/usage` | GET | `?account_id&return_url` | `{ url }` | `Authorization`, `X-Tenant-ID` | user |
| `/billing-management/reports/usage` | GET | - | `{ usage: [] }` | `Authorization`, `X-Tenant-ID` | admin |

## 8. Advanced RBAC & Permissions UI

### What
- Role management, permission assignment, user/role matrix
- UI for viewing and editing RBAC policies

### How
- Next.js RSC for roles/permissions screens
- Zod for validation
- RBAC: admin/owner only

### When
- **Post-MVP**

### Where
- `/admin/rbac`, `/admin/roles`, `/admin/permissions`

### Who
- Frontend team (RBAC specialist)
- Backend team (RBAC endpoints)

### API (sample)
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/rbac/roles` | GET/POST | `{ ... }` | `{ roles: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/rbac/roles/:id` | GET/PUT/DELETE | `{ ... }` | `{ ... }` | `Authorization`, `X-Tenant-ID` | admin |
| `/rbac/permissions` | GET | - | `{ permissions: [] }` | `Authorization`, `X-Tenant-ID` | admin |

## 9. Multi-Currency & Localization

### What
- Currency selection, display, and conversion
- Localized UI (i18n), date/number formatting

### How
- Use i18next or similar for translations
- Currency selector in user/org settings
- TanStack Query for exchange rates

### When
- **Post-MVP**

### Where
- `/settings/currency`, `/settings/localization`

### Who
- Frontend team (i18n/currency specialist)
- Backend team (exchange rate endpoints)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/tenant-currency` | GET/POST | `{ currency }` | `{ currency }` | `Authorization`, `X-Tenant-ID` | user/admin |
| `/exchange-rates` | GET | - | `{ rates: [] }` | `Authorization`, `X-Tenant-ID` | user/admin |

## 10. Audit Log & Compliance Screens

### What
- View audit logs for billing, security, user actions
- Export logs for compliance

### How
- Next.js RSC for audit log tables
- Download/export as CSV/JSON
- RBAC: admin only

### When
- **Post-MVP**

### Where
- `/admin/audit-logs`, `/admin/compliance`

### Who
- Frontend team (compliance specialist)
- Backend team (audit endpoints)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/audit/logs` | GET | `{ ...filters }` | `{ logs: [], total }` | `Authorization`, `X-Tenant-ID` | admin |
| `/audit/logs/export` | GET | `{ format }` | file | `Authorization`, `X-Tenant-ID` | admin |

## 11. Plugin Marketplace & Configuration

### What
- UI for browsing, enabling, configuring plugins (payments, tax, etc)
- Plugin status, config forms, enable/disable

### How
- Next.js RSC for plugin marketplace/config screens
- Dynamic forms for plugin config
- RBAC: admin only

### When
- **Post-MVP**

### Where
- `/admin/plugins`, `/admin/plugins/:name`

### Who
- Frontend team (plugin specialist)
- Backend team (plugin endpoints)

### API
| Endpoint | Method | Request | Response | Headers | RBAC |
|----------|--------|---------|----------|---------|------|
| `/billing-management/plugins/:type` | GET | - | `{ plugins: [] }` | `Authorization`, `X-Tenant-ID` | admin |
| `/billing-management/plugins/:type/:name`