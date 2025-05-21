# Billing Account API Documentation

## `/billing-management/accounts` (POST)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
- **Request (Body):**
```json
{
  "project_id": "string (required for project type)",
  "user_id": "string (required for user type)",
  "org_id": "string (required for organization type)",
  "tenant_id": "string (required)",
  "email": "string (required)",
  "status": "string (required)",
  "currency": "string (optional, defaults to USD)"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (201):**
```json
{
  "id": "string (hashed)",
  "project_id": "string (if project type)",
  "user_id": "string (if user type)",
  "org_id": "string (if organization type)",
  "tenant_id": "string",
  "email": "string",
  "status": "string",
  "currency": "string",
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "invalid input",
  "code": "VALIDATION_ERROR"
}
```
- **RBAC:** Admin (must have `account:create` permission)

---

## `/billing-management/accounts/:id` (GET)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "project_id": "string (if project type)",
  "user_id": "string (if user type)",
  "org_id": "string (if organization type)",
  "tenant_id": "string",
  "email": "string",
  "status": "string",
  "currency": "string",
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Account not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `account:read` permission)

---

## `/billing-management/accounts/:id` (PUT)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
- **Request (Body):**
```json
{
  "project_id": "string (for project type)",
  "user_id": "string (for user type)",
  "org_id": "string (for organization type)",
  "tenant_id": "string",
  "email": "string",
  "status": "string",
  "currency": "string"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "project_id": "string (if project type)",
  "user_id": "string (if user type)",
  "org_id": "string (if organization type)",
  "tenant_id": "string",
  "email": "string",
  "status": "string",
  "currency": "string",
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "invalid input",
  "code": "VALIDATION_ERROR"
}
```
- **RBAC:** Admin (must have `account:update` permission)

---

## `/billing-management/accounts/:id` (DELETE)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "failed to delete account",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `account:delete` permission)

---

## `/billing-management/accounts` (GET)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
  - `project_id`: string (optional, for project type)
  - `user_id`: string (optional, for user type)
  - `org_id`: string (optional, for organization type)
  - `page`: integer (optional, default 1)
  - `page_size`: integer (optional, default 100)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "accounts": [
    {
      "id": "string (hashed)",
      "project_id": "string (if project type)",
      "user_id": "string (if user type)",
      "org_id": "string (if organization type)",
      "tenant_id": "string",
      "email": "string",
      "status": "string",
      "currency": "string",
      "created_at": "string (ISO8601)",
      "updated_at": "string (ISO8601)"
    }
  ],
  "page": 1,
  "page_size": 100
}
```
- **Response (Error):**
```json
{
  "error": "failed to list accounts",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `account:read` permission)

---

## `/billing-management/accounts/:id/action` (POST)
- **Request (Query Params):**
  - `type`: string (optional, default "project", options: "project", "user", "organization")
- **Request (Body):**
```json
{
  "action": "string (required)",
  "params": {
    "key1": "value1",
    "key2": "value2"
  }
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "action": "string",
  "status": "string",
  "result": {
    "key1": "value1"
  }
}
```
- **Response (Error):**
```json
{
  "error": "action required",
  "code": "VALIDATION_ERROR"
}
```
- **RBAC:** Admin (must have `account:action` permission)

---

## Common Account Actions

The following actions can be performed using the `/billing-management/accounts/:id/action` endpoint:

### 1. Suspend Account
- **Action:** `suspend`
- **Params:** None
- **Response:**
```json
{
  "action": "suspend",
  "status": "success",
  "account_id": "string (hashed)",
  "previous_status": "string",
  "current_status": "suspended"
}
```

### 2. Activate Account
- **Action:** `activate`
- **Params:** None
- **Response:**
```json
{
  "action": "activate",
  "status": "success",
  "account_id": "string (hashed)",
  "previous_status": "string",
  "current_status": "active"
}
```

### 3. Change Currency
- **Action:** `change_currency`
- **Params:**
```json
{
  "currency": "string (required, e.g., USD, EUR, GBP)"
}
```
- **Response:**
```json
{
  "action": "change_currency",
  "status": "success",
  "account_id": "string (hashed)",
  "previous_currency": "string",
  "current_currency": "string"
}
```

### 4. Change Default Payment Method
- **Action:** `set_default_payment_method`
- **Params:**
```json
{
  "payment_method_id": "string (required)"
}
```
- **Response:**
```json
{
  "action": "set_default_payment_method",
  "status": "success",
  "account_id": "string (hashed)",
  "payment_method_id": "string"
}
```

### 5. Create External Account
- **Action:** `create_external_account`
- **Params:**
```json
{
  "provider": "string (required, e.g., stripe, paypal)",
  "idempotency_key": "string (optional)"
}
```
- **Response:**
```json
{
  "action": "create_external_account",
  "status": "success",
  "account_id": "string (hashed)",
  "external_id": "string",
  "provider": "string"
}
```

### 6. Update Contact Email
- **Action:** `update_email`
- **Params:**
```json
{
  "email": "string (required)"
}
```
- **Response:**
```json
{
  "action": "update_email",
  "status": "success",
  "account_id": "string (hashed)",
  "previous_email": "string",
  "current_email": "string"
}
```

### Account Status Values

The `status` field in account objects can have the following values:
- `pending` - Account is created but not fully set up
- `active` - Account is active and billable
- `suspended` - Account is temporarily disabled
- `deleted` - Account is marked for deletion

### Account Validation

All account types must include:
- Valid tenant_id
- Valid email
- Valid status

Project accounts must include a valid project_id
User accounts must include a valid user_id
Organization accounts must include a valid org_id 