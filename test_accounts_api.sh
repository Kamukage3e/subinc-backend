#!/bin/bash

set -e

# Configuration
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
API_URL="http://localhost:8080/api/v1/accounts"
AUTH_HEADER="Authorization: Bearer $JWT_TOKEN"
CONTENT_TYPE="Content-Type: application/json"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
function log_info() {
  echo -e "${BLUE}INFO: $1${NC}"
}

function log_success() {
  echo -e "${GREEN}SUCCESS: $1${NC}"
}

function log_error() {
  echo -e "${RED}ERROR: $1${NC}"
}

# Function to make API calls and display results
function call_api() {
  local method=$1
  local endpoint=$2
  local data=$3
  local description=$4

  echo "-------------------------------------------------------------"
  log_info "TEST: $description"
  echo "Method: $method"
  echo "Endpoint: $endpoint"
  if [ ! -z "$data" ]; then
    echo "Payload: $data"
  fi
  
  local response=""
  local status_code=""

  if [ "$method" == "GET" ]; then
    response=$(curl -s -w "\n%{http_code}" -X $method -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$endpoint")
  else
    response=$(curl -s -w "\n%{http_code}" -X $method -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d "$data" "$endpoint")
  fi

  # Extract status code from the last line
  status_code=$(echo "$response" | tail -n1)
  # Extract the JSON response (excluding the status code)
  body=$(echo "$response" | sed '$d')

  # Pretty print the JSON if possible
  if [ "$status_code" -ge 200 ] && [ "$status_code" -lt 300 ]; then
    log_success "Status Code: $status_code"
    if [ ! -z "$body" ]; then
      echo "Response:"
      echo "$body" | jq . 2>/dev/null || echo "$body"
    fi
  else
    log_error "Status Code: $status_code"
    if [ ! -z "$body" ]; then
      echo "Response:"
      echo "$body" | jq . 2>/dev/null || echo "$body"
    fi
  fi
  
  echo ""
  
  # Return the response body for potential usage
  echo "$body"
}

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  log_info "jq is not installed. JSON responses won't be prettified."
fi

log_info "Starting Account API Tests"
echo "API URL: $API_URL"
echo ""

# Test 1: Create Project Billing Account
project_account_data=$(call_api "POST" "$API_URL?type=project" '{
  "project_id": "proj-123",
  "tenant_id": "tenant-456",
  "email": "project-billing@example.com",
  "status": "active",
  "currency": "USD"
}' "Create Project Billing Account")

# Extract the account ID for further tests
project_account_id=$(echo "$project_account_data" | jq -r '.id' 2>/dev/null)

if [ "$project_account_id" != "null" ] && [ ! -z "$project_account_id" ]; then
  log_success "Created project account with ID: $project_account_id"
  
  # Test 2: Get Project Billing Account
  call_api "GET" "$API_URL/$project_account_id?type=project" "" "Get Project Billing Account"
  
  # Test 3: Update Project Billing Account
  call_api "PUT" "$API_URL/$project_account_id?type=project" '{
    "project_id": "proj-123",
    "tenant_id": "tenant-456",
    "email": "updated-project@example.com",
    "status": "active",
    "currency": "EUR"
  }' "Update Project Billing Account"
  
  # Test 4: Perform Action on Project Billing Account
  call_api "POST" "$API_URL/$project_account_id/action?type=project" '{
    "action": "suspend",
    "params": {}
  }' "Suspend Project Billing Account"
fi

# Test 5: Create User Billing Account
user_account_data=$(call_api "POST" "$API_URL?type=user" '{
  "user_id": "user-789",
  "tenant_id": "tenant-456",
  "email": "user-billing@example.com",
  "status": "active",
  "currency": "USD"
}' "Create User Billing Account")

# Extract the account ID for further tests
user_account_id=$(echo "$user_account_data" | jq -r '.id' 2>/dev/null)

if [ "$user_account_id" != "null" ] && [ ! -z "$user_account_id" ]; then
  log_success "Created user account with ID: $user_account_id"
  
  # Test 6: Get User Billing Account
  call_api "GET" "$API_URL/$user_account_id?type=user" "" "Get User Billing Account"
fi

# Test 7: Create Organization Billing Account
org_account_data=$(call_api "POST" "$API_URL?type=organization" '{
  "org_id": "org-101112",
  "tenant_id": "tenant-456",
  "email": "org-billing@example.com",
  "status": "active",
  "currency": "USD"
}' "Create Organization Billing Account")

# Extract the account ID for further tests
org_account_id=$(echo "$org_account_data" | jq -r '.id' 2>/dev/null)

if [ "$org_account_id" != "null" ] && [ ! -z "$org_account_id" ]; then
  log_success "Created organization account with ID: $org_account_id"
  
  # Test 8: Get Organization Billing Account
  call_api "GET" "$API_URL/$org_account_id?type=organization" "" "Get Organization Billing Account"
fi

# Test 9: List all accounts for a tenant
call_api "GET" "$API_URL?tenant_id=tenant-456" "" "List All Accounts for Tenant"

# Test 10: Delete accounts if created
if [ "$project_account_id" != "null" ] && [ ! -z "$project_account_id" ]; then
  call_api "DELETE" "$API_URL/$project_account_id?type=project" "" "Delete Project Billing Account"
fi

if [ "$user_account_id" != "null" ] && [ ! -z "$user_account_id" ]; then
  call_api "DELETE" "$API_URL/$user_account_id?type=user" "" "Delete User Billing Account"
fi

if [ "$org_account_id" != "null" ] && [ ! -z "$org_account_id" ]; then
  call_api "DELETE" "$API_URL/$org_account_id?type=organization" "" "Delete Organization Billing Account"
fi

log_info "Account API Tests Completed" 