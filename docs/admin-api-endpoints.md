# Admin API Endpoints: Full Reference

All endpoints are production-grade, RESTful, and return JSON. All errors are user-friendly and never leak sensitive info. All endpoints require authentication and proper authorization.

---

## Users

### Create User
- **POST** `/api/v1/admin/users`
#### Request
```json
{
  "username": "admin",
  "email": "admin@acme.com",
  "password_hash": "<bcrypt>",
  "roles": ["superuser"],
  "is_active": true
}
```
#### Response (201)
```json
{
  "id": "<uuid>",
  "username": "admin",
  "email": "admin@acme.com",
  "roles": ["superuser"],
  "is_active": true,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### List Users
- **GET** `/api/v1/admin/users`
#### Query Params
- `q`, `role`, `sort_by`, `sort_dir`, `limit`, `offset`
#### Response (200)
```json
{
  "users": [
    {
      "id": "<uuid>",
      "username": "admin",
      "email": "admin@acme.com",
      "roles": ["superuser"],
      "is_active": true,
      "created_at": "2024-05-09T00:00:00Z",
      "updated_at": "2024-05-09T00:00:00Z"
    }
  ],
  "total": 1
}
```

### Get User
- **GET** `/api/v1/admin/users/:id`
#### Response (200)
```json
{
  "id": "<uuid>",
  "username": "admin",
  "email": "admin@acme.com",
  "roles": ["superuser"],
  "is_active": true,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### Update User
- **PUT** `/api/v1/admin/users/:id`
#### Request
```json
{
  "username": "admin2",
  "email": "admin2@acme.com",
  "roles": ["admin"],
  "is_active": false
}
```
#### Response (200)
```json
{
  "id": "<uuid>",
  "username": "admin2",
  "email": "admin2@acme.com",
  "roles": ["admin"],
  "is_active": false,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T01:00:00Z"
}
```

### Delete User
- **DELETE** `/api/v1/admin/users/:id`
#### Response (200)
```json
{
  "success": true
}
```

---

## Tenants

### Create Tenant
- **POST** `/api/v1/admin/tenants`
#### Request
```json
{
  "name": "Acme Tenant",
  "email": "tenant@acme.com",
  "is_active": true,
  "metadata": {}
}
```
#### Response (201)
```json
{
  "id": "<uuid>",
  "name": "Acme Tenant",
  "email": "tenant@acme.com",
  "is_active": true,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z",
  "metadata": {}
}
```

### List Tenants
- **GET** `/api/v1/admin/tenants`
#### Query Params
- `q`, `sort_by`, `sort_dir`, `limit`, `offset`
#### Response (200)
```json
{
  "tenants": [
    {
      "id": "<uuid>",
      "name": "Acme Tenant",
      "email": "tenant@acme.com",
      "is_active": true,
      "created_at": "2024-05-09T00:00:00Z",
      "updated_at": "2024-05-09T00:00:00Z",
      "metadata": {}
    }
  ],
  "total": 1
}
```

### Get Tenant
- **GET** `/api/v1/admin/tenants/:id`
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "Acme Tenant",
  "email": "tenant@acme.com",
  "is_active": true,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z",
  "metadata": {}
}
```

### Update Tenant
- **PUT** `/api/v1/admin/tenants/:id`
#### Request
```json
{
  "name": "Acme Tenant Updated",
  "email": "tenant2@acme.com",
  "is_active": false
}
```
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "Acme Tenant Updated",
  "email": "tenant2@acme.com",
  "is_active": false,
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T01:00:00Z",
  "metadata": {}
}
```

### Delete Tenant
- **DELETE** `/api/v1/admin/tenants/:id`
#### Response (204)
No content

---

## Roles

### Create Role
- **POST** `/api/v1/admin/roles`
#### Request
```json
{
  "name": "admin",
  "permissions": ["read", "write"],
  "description": "Admin role"
}
```
#### Response (201)
```json
{
  "id": "<uuid>",
  "name": "admin",
  "permissions": ["read", "write"],
  "description": "Admin role",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### List Roles
- **GET** `/api/v1/admin/roles`
#### Query Params
- `q`, `sort_by`, `sort_dir`, `limit`, `offset`
#### Response (200)
```json
{
  "roles": [
    {
      "id": "<uuid>",
      "name": "admin",
      "permissions": ["read", "write"],
      "description": "Admin role",
      "created_at": "2024-05-09T00:00:00Z",
      "updated_at": "2024-05-09T00:00:00Z"
    }
  ],
  "total": 1
}
```

### Get Role
- **GET** `/api/v1/admin/roles/:id`
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "admin",
  "permissions": ["read", "write"],
  "description": "Admin role",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### Update Role
- **PUT** `/api/v1/admin/roles/:id`
#### Request
```json
{
  "name": "admin2",
  "permissions": ["read"],
  "description": "Updated role"
}
```
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "admin2",
  "permissions": ["read"],
  "description": "Updated role",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T01:00:00Z"
}
```

### Delete Role
- **DELETE** `/api/v1/admin/roles/:id`
#### Response (204)
No content

---

## Permissions

### Create Permission
- **POST** `/api/v1/admin/permissions`
#### Request
```json
{
  "name": "read",
  "description": "Read permission"
}
```
#### Response (201)
```json
{
  "id": "<uuid>",
  "name": "read",
  "description": "Read permission",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### List Permissions
- **GET** `/api/v1/admin/permissions`
#### Query Params
- `q`, `sort_by`, `sort_dir`, `limit`, `offset`
#### Response (200)
```json
{
  "permissions": [
    {
      "id": "<uuid>",
      "name": "read",
      "description": "Read permission",
      "created_at": "2024-05-09T00:00:00Z",
      "updated_at": "2024-05-09T00:00:00Z"
    }
  ],
  "total": 1
}
```

### Get Permission
- **GET** `/api/v1/admin/permissions/:id`
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "read",
  "description": "Read permission",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### Update Permission
- **PUT** `/api/v1/admin/permissions/:id`
#### Request
```json
{
  "name": "read-updated",
  "description": "Updated permission"
}
```
#### Response (200)
```json
{
  "id": "<uuid>",
  "name": "read-updated",
  "description": "Updated permission",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T01:00:00Z"
}
```

### Delete Permission
- **DELETE** `/api/v1/admin/permissions/:id`
#### Response (204)
No content

---

## Audit Logs

### List Audit Logs
- **GET** `/api/v1/admin/audit-logs`
#### Query Params
- `actor_id`, `action`, `resource`, `start`, `end`, `limit`, `offset`, `export`
#### Response (200)
```json
{
  "total": 1,
  "logs": [
    {
      "id": "<uuid>",
      "actor_id": "<uuid>",
      "action": "create",
      "resource": "org",
      "details": {},
      "created_at": "2024-05-09T00:00:00Z"
    }
  ]
}
```

---

## API Keys

### List API Keys
- **GET** `/api/v1/admin/api-keys`
#### Query Params
- `user_id`, `status`, `limit`, `offset`
#### Response (200)
```json
{
  "total": 1,
  "api_keys": [
    {
      "id": "<uuid>",
      "user_id": "<uuid>",
      "name": "Key 1",
      "status": "active",
      "created_at": "2024-05-09T00:00:00Z",
      "updated_at": "2024-05-09T00:00:00Z"
    }
  ]
}
```

### Create API Key
- **POST** `/api/v1/admin/api-keys`
#### Request
```json
{
  "user_id": "<uuid>",
  "name": "Key 1"
}
```
#### Response (201)
```json
{
  "id": "<uuid>",
  "user_id": "<uuid>",
  "name": "Key 1",
  "status": "active",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### Get API Key
- **GET** `/api/v1/admin/api-keys/:id`
#### Response (200)
```json
{
  "id": "<uuid>",
  "user_id": "<uuid>",
  "name": "Key 1",
  "status": "active",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T00:00:00Z"
}
```

### Update API Key
- **PUT** `/api/v1/admin/api-keys/:id`
#### Request
```json
{
  "name": "Key 1 Updated"
}
```
#### Response (200)
```json
{
  "id": "<uuid>",
  "user_id": "<uuid>",
  "name": "Key 1 Updated",
  "status": "active",
  "created_at": "2024-05-09T00:00:00Z",
  "updated_at": "2024-05-09T01:00:00Z"
}
```

### Revoke API Key
- **DELETE** `/api/v1/admin/api-keys/:id`
#### Response (204)
No content

---

## Error Response (all endpoints)
```json
{
  "error": "user-friendly error message"
}
``` 