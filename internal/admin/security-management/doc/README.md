# Security Management API

## Overview

The Security Management module provides a comprehensive set of REST APIs for managing security within the platform. This includes authentication, MFA, session management, API keys, device management, and security policies.

## RESTful Design Principles

The API follows standard REST practices:

- Resources are represented as nouns (e.g., `/users`, `/policies`)
- Actions are performed using appropriate HTTP methods:
  - `GET` for retrieval
  - `POST` for creation
  - `PUT` for updates
  - `DELETE` for removal
- Resources are organized hierarchically (e.g., `/users/:user_id/devices/:device_id`)
- Standard HTTP status codes indicate success/failure
- Consistent response format with metadata

## Resource Endpoints

### Authentication

- `POST /api/v1/auth/login` - Login with credentials
- `POST /api/v1/auth/logout` - Logout and invalidate session
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/verify-email` - Verify user email
- `POST /api/v1/auth/resend-verification` - Resend verification email
- `POST /api/v1/auth/change-password` - Change user password
- `POST /api/v1/auth/token/refresh` - Refresh session token

### Users

#### User Profile

- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update current user profile
- `DELETE /api/v1/users/me` - Delete current user account
- `GET /api/v1/users/:user_id` - Get specific user profile (admin)
- `PUT /api/v1/users/:user_id` - Update specific user profile (admin)
- `DELETE /api/v1/users/:user_id` - Delete specific user account (admin)
- `POST /api/v1/users/recover` - Initiate account recovery
- `POST /api/v1/users/consent` - Record user consent

#### Security Events

- `GET /api/v1/users/:user_id/security-events` - List user security events
- `GET /api/v1/users/:user_id/security-events/:event_id` - Get specific security event
- `GET /api/v1/users/:user_id/login-history` - List user login history
- `GET /api/v1/users/:user_id/login-history/:history_id` - Get specific login history item

#### MFA

- `GET /api/v1/users/:user_id/mfa` - Get MFA configuration for user
- `PUT /api/v1/users/:user_id/mfa` - Enable MFA for user
- `DELETE /api/v1/users/:user_id/mfa` - Disable MFA for user
- `GET /api/v1/users/:user_id/mfa/challenge` - Generate MFA challenge
- `POST /api/v1/users/:user_id/mfa/verify` - Verify MFA challenge

#### API Keys

- `GET /api/v1/users/:user_id/api-keys` - List user API keys
- `POST /api/v1/users/:user_id/api-keys` - Create user API key
- `DELETE /api/v1/users/:user_id/api-keys/:key_id` - Revoke user API key

#### Devices

- `GET /api/v1/users/:user_id/devices` - List user devices
- `DELETE /api/v1/users/:user_id/devices/:device_id` - Revoke user device
- `PUT /api/v1/users/:user_id/devices/:device_id/trust` - Trust specific device

#### Sessions

- `GET /api/v1/users/:user_id/sessions` - List user sessions
- `POST /api/v1/users/:user_id/sessions` - Create user session
- `GET /api/v1/users/:user_id/sessions/:session_id` - Get specific session
- `DELETE /api/v1/users/:user_id/sessions/:session_id` - Delete session
- `DELETE /api/v1/users/:user_id/sessions/:session_id/revoke` - Revoke session

#### Password Management

- `POST /api/v1/users/:user_id/password/reset` - Reset user password (admin)

### Password Reset

- `POST /api/v1/password-reset/request` - Request password reset token
- `POST /api/v1/password-reset/tokens/:token/verify` - Verify password reset token
- `POST /api/v1/password-reset/tokens/:token/redeem` - Use password reset token

### Audit Logs

- `GET /api/v1/audit-logs` - List security audit logs
- `GET /api/v1/audit-logs/:log_id` - Get specific audit log

### Security Breaches

- `GET /api/v1/breaches` - List security breaches
- `GET /api/v1/breaches/:breach_id` - Get specific breach

### Security Policies

- `GET /api/v1/policies` - List security policies
- `POST /api/v1/policies` - Create security policy
- `PUT /api/v1/policies/:policy_id` - Update specific policy
- `DELETE /api/v1/policies/:policy_id` - Delete specific policy

### Webhooks

- `GET /api/v1/webhooks/tenants/:tenant_id` - List tenant webhooks
- `POST /api/v1/webhooks/tenants/:tenant_id` - Create tenant webhook
- `DELETE /api/v1/webhooks/tenants/:tenant_id/:webhook_id` - Delete specific webhook
- `POST /api/v1/webhooks/tenants/:tenant_id/:webhook_id/trigger` - Trigger specific webhook

### Invites

- `POST /api/v1/invites` - Send user invite
- `POST /api/v1/invites/accept` - Accept user invite

### Notifications

- `GET /api/v1/notifications/providers/status` - Get notification provider status
- `POST /api/v1/notifications/queue/retry` - Retry notification queue
- `GET /api/v1/notifications/tenants/:tenant_id/config` - Get tenant notification config
- `PUT /api/v1/notifications/tenants/:tenant_id/config` - Update tenant notification config
- `POST /api/v1/notifications/tenants/:tenant_id/test` - Send test notification
- `GET /api/v1/notifications/tenants/:tenant_id/channels/:channel/providers/:provider/status` - Get channel provider status
- `PUT /api/v1/notifications/tenants/:tenant_id/channels/:channel/providers/:provider/status` - Update channel provider status
- `GET /api/v1/notifications/tenants/:tenant_id/providers/:provider/config` - Get provider config
- `PUT /api/v1/notifications/tenants/:tenant_id/providers/:provider/config` - Update provider config

### Configuration

- `GET /api/v1/configs/tenants/:tenant_id/security` - Get security module config
- `PUT /api/v1/configs/tenants/:tenant_id/security` - Update security module config
- `GET /api/v1/configs/tenants/:tenant_id/password-policy` - Get password policy config
- `PUT /api/v1/configs/tenants/:tenant_id/password-policy` - Update password policy config
- `GET /api/v1/configs/tenants/:tenant_id/session` - Get session config
- `PUT /api/v1/configs/tenants/:tenant_id/session` - Update session config

### Rate Limits

- `GET /api/v1/rate-limits/:scope/:scope_id` - Get rate limit for scope
- `PUT /api/v1/rate-limits/:scope/:scope_id` - Update rate limit for scope
- `DELETE /api/v1/rate-limits/:rate_limit_id` - Delete specific rate limit

### Self Service

- `GET /api/v1/self-service/security` - Get self-service security info

### Security Analytics

- `GET /api/v1/analytics/tenants/:tenant_id/security` - Get security analytics
- `GET /api/v1/analytics/tenants/:tenant_id/anomalies` - List security anomalies
- `GET /api/v1/analytics/tenants/:tenant_id/anomalies/:anomaly_id` - Get specific anomaly

## Response Format

All API responses follow a consistent format:

```json
// For resource lists
{
  "resources": [...],  // The actual resources (users, policies, etc.)
  "count": 10,         // Total count in this response
  "total": 50,         // Total available (for pagination)
  "page": 1,           // Current page (if paginated)
  "page_size": 10,     // Items per page (if paginated)
  "metadata": {        // Additional metadata
    "resource_id": "...",
    "other_field": "..."
  }
}

// For single resources
{
  "id": "...",
  "field1": "...",
  "field2": "...",
  ...
}

// For operations
{
  "success": true,
  "metadata": {
    "resource_id": "..."
  }
}

// For errors
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {...}  // Optional additional error details
}
```

## Authentication and Authorization

Most endpoints require authentication via JWT bearer token provided in the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

Certain endpoints additionally require specific permissions, which are enforced via RBAC. 