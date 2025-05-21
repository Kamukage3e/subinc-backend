# Organization & Tenant Management API Details

## `/tenant-management/tenants` (GET)
- **Request (Query Params):**
  - `query`: string (optional, search by name)
  - `sort_by`: string (optional)
  - `sort_dir`: string (optional, asc|desc)
  - `limit`: integer (optional, default 100)
  - `offset`: integer (optional, default 0)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "tenants": [
    {
      "id": "string (hashed)",
      "name": "string",
      "status": "pending|active|suspended|deleted",
      "settings": "object (JSON)",
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
  "error": "Failed to list tenants",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `tenant:read` permission)

---

## `/tenant-management/tenants` (POST)
- **Request:**
```json
{
  "name": "string (required, unique)",
  "settings": { "key": "value" }
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (201):**
```json
{
  "id": "string (hashed)",
  "name": "string",
  "status": "pending|active|suspended|deleted",
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
- **RBAC:** Admin (must have `tenant:create` permission)

---

## `/tenant-management/tenants/:id` (GET)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "name": "string",
  "status": "pending|active|suspended|deleted",
  "settings": "object (JSON)",
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "Tenant not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `tenant:read` permission)

---

## `/tenant-management/tenants/:id` (PUT)
- **Request:**
```json
{
  "name": "string (optional)",
  "settings": { "key": "value" },
  "status": "pending|active|suspended|deleted" (optional)
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "name": "string",
  "status": "pending|active|suspended|deleted",
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
- **RBAC:** Admin (must have `tenant:update` permission)

---

## `/tenant-management/tenants/:id` (DELETE)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "Tenant not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `tenant:delete` permission)

---

## `/users` (GET)
- **Request (Query Params):**
  - `status`: string (optional)
  - `page`: integer (optional, default 1)
  - `page_size`: integer (optional, default 50)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "users": [
    {
      "id": "string (hashed)",
      "email": "string",
      "status": "active|invited|suspended|deleted",
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
  "error": "Failed to list users",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin (must have `user:read` permission)

---

## `/users` (POST)
- **Request:**
```json
{
  "email": "string (required, valid email)",
  "status": "active|invited|suspended|deleted" (optional)
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (201):**
```json
{
  "id": "string (hashed)",
  "email": "string",
  "status": "active|invited|suspended|deleted",
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
- **RBAC:** Admin (must have `user:create` permission)

---

## `/users/:id` (GET)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "email": "string",
  "status": "active|invited|suspended|deleted",
  "created_at": "string (ISO8601)",
  "updated_at": "string (ISO8601)"
}
```
- **Response (Error):**
```json
{
  "error": "User not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `user:read` permission)

---

## `/users/:id` (PUT)
- **Request:**
```json
{
  "email": "string (optional, valid email)",
  "status": "active|invited|suspended|deleted" (optional)
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "id": "string (hashed)",
  "email": "string",
  "status": "active|invited|suspended|deleted",
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
- **RBAC:** Admin (must have `user:update` permission)

---

## `/users/:id` (DELETE)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "User not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `user:delete` permission)

---

## `/users/:id/orgs` (GET)
- **Request:** None (path param: `id`)
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (200):**
```json
{
  "orgs": [
    {
      "id": "string (hashed)",
      "name": "string",
      "role": "string",
      "status": "active|invited|suspended|deleted",
      "created_at": "string (ISO8601)"
    }
  ]
}
```
- **Response (Error):**
```json
{
  "error": "Failed to list orgs",
  "code": "INTERNAL_ERROR"
}
```
- **RBAC:** Admin or user (must have `org:read` permission)

---

## `/users/:id/orgs` (POST)
- **Request:**
```json
{
  "org_id": "string (hashed, required)",
  "role": "string (required)"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (201):**
```json
{
  "id": "string (hashed)",
  "org_id": "string (hashed)",
  "role": "string",
  "status": "active|invited|suspended|deleted",
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
- **RBAC:** Admin (must have `org:add_user` permission)

---

## `/users/:id/orgs` (DELETE)
- **Request:**
```json
{
  "org_id": "string (hashed, required)"
}
```
- **Headers:**
  - `Authorization: Bearer <session_token>` (required)
  - `X-Tenant-ID: <tenant_id>` (required)
- **Response (204):** No content
- **Response (Error):**
```json
{
  "error": "Org or user not found",
  "code": "NOT_FOUND"
}
```
- **RBAC:** Admin (must have `org:remove_user` permission)

--- 