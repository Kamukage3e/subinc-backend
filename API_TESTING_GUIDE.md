# SubInc Backend API Testing Guide

This document provides a guide for testing the Organization and Project Management APIs of the SubInc Backend system. It includes details about API endpoints, request/response formats, and curl examples for testing each endpoint.

## Authentication

All API endpoints require authentication via a JWT token in the Authorization header.

```bash
Authorization: Bearer <your_jwt_token>
```

## Organization Management API

### Base URL
```
http://localhost:8080/api/v1/organizations
```

### 1. List Organizations

**Endpoint:** `GET /organizations`

**Query Parameters:**
- `page` (optional, default: 1): The page number for pagination
- `page_size` (optional, default: 100): Number of items per page
- `owner_id` (optional): Filter organizations by owner ID

**Response:**
```json
{
  "organizations": [
    {
      "id": "uuid-string",
      "name": "Organization Name",
      "slug": "organization-slug",
      "owner_id": "uuid-string",
      "status": "active",
      "created_at": "2025-05-10T15:48:15.616632Z",
      "updated_at": "2025-05-10T15:48:15.616632Z"
    }
  ],
  "page": 1,
  "page_size": 100
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/organizations" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 2. Create Organization

**Endpoint:** `POST /organizations`

**Request Body:**
```json
{
  "name": "Organization Name",
  "slug": "organization-slug",
  "owner_id": "uuid-string",
  "status": "active"
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "name": "Organization Name",
  "slug": "organization-slug",
  "owner_id": "uuid-string",
  "status": "active",
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X POST "http://localhost:8080/api/v1/organizations" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Organization",
    "slug": "test-org",
    "owner_id": "afdb1105-daf2-4c14-91c8-4ad70bc2bfa7",
    "status": "active"
  }'
```

### 3. Get Organization

**Endpoint:** `GET /organizations/{id}`

**Response:**
```json
{
  "id": "uuid-string",
  "name": "Organization Name",
  "slug": "organization-slug",
  "owner_id": "uuid-string",
  "status": "active",
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/organizations/YOUR_ORG_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 4. Update Organization

**Endpoint:** `PUT /organizations/{id}`

**Request Body:**
```json
{
  "name": "Updated Organization Name",
  "slug": "updated-slug",
  "owner_id": "uuid-string",
  "status": "active"
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "name": "Updated Organization Name",
  "slug": "updated-slug",
  "owner_id": "uuid-string",
  "status": "active",
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X PUT "http://localhost:8080/api/v1/organizations/YOUR_ORG_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Organization",
    "slug": "updated-org",
    "owner_id": "afdb1105-daf2-4c14-91c8-4ad70bc2bfa7",
    "status": "active"
  }'
```

### 5. Delete Organization

**Endpoint:** `DELETE /organizations/{id}`

**Response:**
Status: 204 No Content

**Curl Example:**
```bash
curl -X DELETE "http://localhost:8080/api/v1/organizations/YOUR_ORG_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 6. Get Organization Settings

**Endpoint:** `GET /organizations/{id}/settings`

**Response:**
```json
{
  "default_currency": "USD",
  "default_language": "en",
  "enable_notifications": true,
  "retention_period_days": 30
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/organizations/YOUR_ORG_ID/settings" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 7. Update Organization Settings

**Endpoint:** `PUT /organizations/{id}/settings`

**Request Body:**
```json
{
  "settings": {
    "default_currency": "USD",
    "default_language": "en",
    "enable_notifications": true,
    "retention_period_days": 30
  }
}
```

**Response:**
```json
{
  "ok": true
}
```

**Curl Example:**
```bash
curl -X PUT "http://localhost:8080/api/v1/organizations/YOUR_ORG_ID/settings" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "default_currency": "USD",
      "default_language": "en",
      "enable_notifications": true,
      "retention_period_days": 30
    }
  }'
```

## Project Management API

### Base URL
```
http://localhost:8080/api/v1/projects
```

### 1. List Projects

**Endpoint:** `GET /projects`

**Query Parameters:**
- `page` (optional, default: 1): The page number for pagination
- `page_size` (optional, default: 100): Number of items per page
- `org_id` (optional): Filter projects by organization ID

**Response:**
```json
{
  "projects": [
    {
      "id": "uuid-string",
      "org_id": "uuid-string",  // may be omitted if no organization is associated
      "name": "Project Name",
      "description": "Project description",
      "status": "active",
      "tags": {
        "type": "test",
        "env": "development"
      },
      "created_at": "2025-05-10T15:48:15.616632Z",
      "updated_at": "2025-05-10T15:48:15.616632Z"
    }
  ],
  "page": 1,
  "page_size": 100
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/projects" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 2. Create Project (without organization)

**Endpoint:** `POST /projects`

**Request Body:**
```json
{
  "name": "Project Name",
  "description": "Project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "development"
  }
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "name": "Project Name",
  "description": "Project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "development"
  },
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X POST "http://localhost:8080/api/v1/projects" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project Without Org",
    "description": "A test project created without an organization association",
    "status": "active",
    "tags": {
      "type": "test",
      "env": "development"
    }
  }'
```

### 3. Create Project (with organization)

**Endpoint:** `POST /projects`

**Request Body:**
```json
{
  "name": "Project Name",
  "org_id": "uuid-string",
  "description": "Project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "development"
  }
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "org_id": "uuid-string",
  "name": "Project Name",
  "description": "Project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "development"
  },
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X POST "http://localhost:8080/api/v1/projects" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project With Org",
    "org_id": "some-valid-org-id",
    "description": "A test project created with an organization association",
    "status": "active",
    "tags": {
      "type": "test",
      "env": "development"
    }
  }'
```

### 4. Get Project

**Endpoint:** `GET /projects/{id}`

**Response:**
```json
{
  "id": "uuid-string",
  "org_id": "uuid-string",  // may be omitted if no organization is associated
  "name": "Project Name",
  "description": "Project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "development"
  },
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/projects/YOUR_PROJECT_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 5. Update Project

**Endpoint:** `PUT /projects/{id}`

**Request Body:**
```json
{
  "name": "Updated Project Name",
  "description": "Updated project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "production"
  }
}
```

**Response:**
```json
{
  "id": "uuid-string",
  "org_id": "uuid-string",  // may be omitted if no organization is associated
  "name": "Updated Project Name",
  "description": "Updated project description",
  "status": "active",
  "tags": {
    "type": "test",
    "env": "production"
  },
  "created_at": "2025-05-10T15:48:15.616632Z",
  "updated_at": "2025-05-10T15:48:15.616632Z"
}
```

**Curl Example:**
```bash
curl -X PUT "http://localhost:8080/api/v1/projects/YOUR_PROJECT_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Project Without Org",
    "description": "This project has been updated without an org ID",
    "status": "active",
    "tags": {
      "type": "test",
      "env": "production"
    }
  }'
```

### 6. Delete Project

**Endpoint:** `DELETE /projects/{id}`

**Response:**
Status: 204 No Content

**Curl Example:**
```bash
curl -X DELETE "http://localhost:8080/api/v1/projects/YOUR_PROJECT_ID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 7. Get Project Settings

**Endpoint:** `GET /projects/{id}/settings`

**Response:**
```json
{
  "notifications_enabled": true,
  "default_branch": "main",
  "auto_deploy": false
}
```

**Curl Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/projects/YOUR_PROJECT_ID/settings" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 8. Update Project Settings

**Endpoint:** `PUT /projects/{id}/settings`

**Request Body:**
```json
{
  "settings": {
    "notifications_enabled": true,
    "default_branch": "main",
    "auto_deploy": false
  }
}
```

**Response:**
```json
{
  "ok": true
}
```

**Curl Example:**
```bash
curl -X PUT "http://localhost:8080/api/v1/projects/YOUR_PROJECT_ID/settings" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "notifications_enabled": true,
      "default_branch": "main",
      "auto_deploy": false
    }
  }'
```

## Running the Test Scripts

Two shell scripts are provided to help test the APIs:

1. `test_org_endpoints.sh`: Tests all organization management endpoints
2. `test_project_endpoints.sh`: Tests all project management endpoints, ensuring the org_id field is correctly treated as optional

To run the scripts:

```bash
# Make the scripts executable
chmod +x test_org_endpoints.sh test_project_endpoints.sh

# Run the organization endpoints test script
./test_org_endpoints.sh

# Run the project endpoints test script
./test_project_endpoints.sh
```

Before running the scripts, make sure:
1. The server is running
2. The JWT token in the scripts is valid
3. Replace placeholder IDs with actual IDs after creating organizations and projects

## Troubleshooting

1. **Authentication Errors (401)**: Ensure your JWT token is valid and not expired
2. **Permission Errors (403)**: Check that your user has the necessary permissions
3. **Not Found Errors (404)**: Verify that the resource IDs exist
4. **Validation Errors (422)**: Make sure all required fields are provided and valid 