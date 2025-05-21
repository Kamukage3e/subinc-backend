#!/bin/bash

set -euo pipefail

   curl -v -X GET http://localhost:8080/api/v1/users/me \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc5MTk5MTIsImlhdCI6MTc0NzgzMzUxMiwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMjFUMTM6MTg6MzIuNzE5MDQyWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMjFUMTM6MTg6MzIuNzE5MDQxWiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTIxVDEzOjE4OjMyLjcxOTA0M1oiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.FFIO4gY1nGynMbLpuz6ZJXM-6RJrD-jxKLCShET36EY"


   curl -v -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@subinc.com","password":"Temp-1716230408"}'

# Configuration
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
AUTH_HEADER="Authorization: Bearer $TOKEN"
CONTENT_TYPE="Content-Type: application/json"
API_URL="http://localhost:8080/api/v1"
ACCOUNTS_API="$API_URL/billing-management/accounts"
ORG_API="$API_URL/organizations"
PROJECT_API="$API_URL/projects"

TENANT_UUID="63a01285-7a0e-4120-a4fb-737ee9b8c148"
USER_ID="afdb1105-daf2-4c14-91c8-4ad70bc2bfa7"
TIMESTAMP=$(date +%s)

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

function print_header() {
  echo -e "\n${YELLOW}==== $1 ====\n${NC}"
}

function check_server() {
  print_header "Checking server status"
  local status_code
  status_code=$(curl -sf -o /dev/null -w "%{http_code}" "$API_URL/health" || echo 0)
  if [[ "$status_code" != "200" ]]; then
    echo -e "${RED}Server not responding (${status_code}). Make sure the server is running.${NC}"
    exit 1
  fi
  echo -e "${GREEN}Server is running.${NC}"
}

function extract_id() {
  local json="$1"
  local id
  id=$(echo "$json" | jq -r '.id // empty')
  if [[ -z "$id" || "$id" == "null" ]]; then
    id=$(uuidgen || echo "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d")
    echo "Failed to extract ID, using fallback ID: $id"
  fi
  echo "$id"
}

function print_status() {
  local name="$1"
  local exists="$2"
  if [[ "$exists" == true ]]; then
    echo -e "  - $name: ${GREEN}EXISTS${NC}"
  else
    echo -e "  - $name: ${RED}MISSING${NC}"
  fi
}

check_server

print_header "Setup: Create Organization via API"
ORG_RESPONSE=$(curl -sf -X POST "$ORG_API" \
  -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
  -d "{\"name\":\"Test Org $TIMESTAMP\",\"slug\":\"test-org-$TIMESTAMP\",\"owner_id\":\"$USER_ID\",\"status\":\"active\"}")
ORG_ID=$(extract_id "$ORG_RESPONSE")
echo "Created org_id: $ORG_ID"

TENANT_UUID="$ORG_ID"

print_header "Setup: Create Project via API"
PROJECT_RESPONSE=$(curl -sf -X POST "$PROJECT_API" \
  -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Test Project $TIMESTAMP\",\"status\":\"active\"}")
PROJECT_ID=$(extract_id "$PROJECT_RESPONSE")
echo "Created project_id: $PROJECT_ID"

ALT_PROJECT_RESPONSE=$(curl -sf -X POST "$PROJECT_API" \
  -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Alt Project $TIMESTAMP\",\"status\":\"active\"}")
ALT_PROJECT_ID=$(extract_id "$ALT_PROJECT_RESPONSE")
echo "Created alt_project_id: $ALT_PROJECT_ID"

print_header "Testing Billing Account API"
echo -e "This script tests the complete CRUD operations for billing accounts\n"

# Test 1: List all accounts (GET)
print_header "TEST 1: List all project billing accounts"
project_list_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API?type=project&project_id=$PROJECT_ID" || true)
echo "$project_list_response" | jq .

# Test 2: Create project billing account (POST)
print_header "TEST 2: Create project billing account"
account_response=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"project_id\": \"$PROJECT_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"project-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"USD\"}" \
  "$ACCOUNTS_API?type=project" || true)
echo "Account creation response: $account_response"
account_id=$(extract_id "$account_response")
echo "Using Account ID: $account_id"

# List and check project account
print_header "TEST 2b: List project billing accounts and check for new account"
project_list_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API?type=project&project_id=$PROJECT_ID" || true)
echo "$project_list_response" | jq .
if echo "$project_list_response" | jq -e --arg id "$account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  echo -e "${GREEN}PASS: Project account found in list${NC}"
else
  echo -e "${RED}FAIL: Project account NOT found in list${NC}"
fi

# Test 3: Get specific account (GET)
print_header "TEST 3: Get account by ID"
project_get_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API/$account_id?type=project")
echo "$project_get_response" | jq .

# Test 4: Update account (PUT)
print_header "TEST 4: Update account"
project_update_response=$(curl -sf -X PUT \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"id\": \"$account_id\", \"project_id\": \"$PROJECT_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"updated-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"EUR\"}" \
  "$ACCOUNTS_API/$account_id?type=project")
echo "$project_update_response" | jq .

# Test 5: Perform account action
print_header "TEST 5: Perform account action (suspend)"
action_response=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"action\": \"suspend\", \"params\": {\"reason\": \"Testing account suspension\"}}" \
  "$ACCOUNTS_API/$account_id/action?type=project" || true)
if jq -e . >/dev/null 2>&1 <<<"$action_response"; then
  echo "$action_response" | jq .
else
  echo "$action_response"
  echo -e "${RED}Invalid JSON response${NC}"
fi

# Test 6: List accounts with pagination
print_header "TEST 6: List accounts with pagination"
curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API?type=project&project_id=$PROJECT_ID&page=1&page_size=10" | jq .

# Test 7: Create user billing account
print_header "TEST 7: Create user billing account"
user_account_response=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"user_id\": \"$USER_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"user-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"USD\"}" \
  "$ACCOUNTS_API?type=user" || true)
echo "User account creation response: $user_account_response"
user_account_id=$(extract_id "$user_account_response")

# List and check user account
print_header "TEST 7b: List user billing accounts and check for new account"
user_list_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API?type=user&user_id=$USER_ID" || true)
echo "$user_list_response" | jq .
if echo "$user_list_response" | jq -e --arg id "$user_account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  echo -e "${GREEN}PASS: User account found in list${NC}"
else
  echo -e "${RED}FAIL: User account NOT found in list${NC}"
fi

# Test 8: Create organization billing account
print_header "TEST 8: Create organization billing account"
org_account_response=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"org_id\": \"$ORG_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"org-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"USD\"}" \
  "$ACCOUNTS_API?type=organization" || true)
echo "Organization account creation response: $org_account_response"
org_account_id=$(extract_id "$org_account_response")

# List and check organization account
print_header "TEST 8b: List organization billing accounts and check for new account"
org_list_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API?type=organization&org_id=$ORG_ID" || true)
echo "$org_list_response" | jq .
if echo "$org_list_response" | jq -e --arg id "$org_account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  echo -e "${GREEN}PASS: Organization account found in list${NC}"
else
  echo -e "${RED}FAIL: Organization account NOT found in list${NC}"
fi

# Test 9: Complete account with additional data
print_header "TEST 9: Create complete account with additional data"
complete_account_response=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"project_id\": \"$ALT_PROJECT_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"complete-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"USD\", \"billing_address\": {\"line1\": \"123 Main St\", \"city\": \"San Francisco\", \"state\": \"CA\", \"postal_code\": \"94107\", \"country\": \"US\"}, \"payment_methods\": [], \"metadata\": {\"description\": \"Complete project billing account\", \"created_by\": \"test_script\", \"timestamp\": \"$TIMESTAMP\"}}" \
  "$ACCOUNTS_API?type=project" || true)
echo "Complete account creation response: $complete_account_response"

# Test 10: Delete account (if created successfully)
if [[ -n "$account_id" && "$account_id" != "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d" ]]; then
  print_header "TEST 10: Delete account"
  delete_response=$(curl -sf -X DELETE -H "$AUTH_HEADER" "$ACCOUNTS_API/$account_id?type=project" -w "\nStatus: %{http_code}" || true)
  echo "$delete_response"
else
  echo -e "\n${YELLOW}Skipping account deletion as no valid account ID was obtained${NC}"
fi

# --- Track test results ---
PROJECT_CREATE_RESULT="FAIL"
PROJECT_LIST_RESULT="FAIL"
PROJECT_GET_RESULT="FAIL"
PROJECT_UPDATE_RESULT="FAIL"
PROJECT_ACTION_RESULT="FAIL"
PROJECT_DELETE_RESULT="FAIL"

USER_CREATE_RESULT="FAIL"
USER_LIST_RESULT="FAIL"
USER_GET_RESULT="FAIL"
USER_UPDATE_RESULT="FAIL"
USER_DELETE_RESULT="FAIL"

ORG_CREATE_RESULT="FAIL"
ORG_LIST_RESULT="FAIL"
ORG_GET_RESULT="FAIL"
ORG_UPDATE_RESULT="FAIL"
ORG_DELETE_RESULT="FAIL"

# Project create
if [[ "$account_id" != "" && "$account_id" != "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d" ]]; then
  PROJECT_CREATE_RESULT="PASS"
fi
# Project list
if echo "$project_list_response" | jq -e --arg id "$account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  PROJECT_LIST_RESULT="PASS"
fi
# Project get
if echo "$project_get_response" | jq -e --arg id "$account_id" '.id == $id' >/dev/null; then
  PROJECT_GET_RESULT="PASS"
fi
# Project update
if echo "$project_update_response" | jq -e --arg email "updated-$TIMESTAMP@example.com" '.email == $email' >/dev/null; then
  PROJECT_UPDATE_RESULT="PASS"
fi
# Project action
if jq -e . >/dev/null 2>&1 <<<"$action_response"; then
  PROJECT_ACTION_RESULT="PASS"
fi
# Project delete
if [[ "$delete_response" == *"Status: 204"* ]]; then
  PROJECT_DELETE_RESULT="PASS"
fi

# User create
if [[ "$user_account_id" != "" && "$user_account_id" != "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d" ]]; then
  USER_CREATE_RESULT="PASS"
fi
# User list
if echo "$user_list_response" | jq -e --arg id "$user_account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  USER_LIST_RESULT="PASS"
fi
# User get
user_get_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API/$user_account_id?type=user")
echo "$user_get_response" | jq .
if echo "$user_get_response" | jq -e --arg id "$user_account_id" '.id == $id' >/dev/null; then
  USER_GET_RESULT="PASS"
fi
# User update
user_update_response=$(curl -sf -X PUT \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"id\": \"$user_account_id\", \"user_id\": \"$USER_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"updated-user-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"EUR\"}" \
  "$ACCOUNTS_API/$user_account_id?type=user")
echo "$user_update_response" | jq .
if echo "$user_update_response" | jq -e --arg email "updated-user-$TIMESTAMP@example.com" '.email == $email' >/dev/null; then
  USER_UPDATE_RESULT="PASS"
fi
# User delete
user_delete_response=$(curl -sf -X DELETE -H "$AUTH_HEADER" "$ACCOUNTS_API/$user_account_id?type=user" -w "\nStatus: %{http_code}" || true)
echo "$user_delete_response"
if [[ "$user_delete_response" == *"Status: 204"* ]]; then
  USER_DELETE_RESULT="PASS"
fi

# Org create
if [[ "$org_account_id" != "" && "$org_account_id" != "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d" ]]; then
  ORG_CREATE_RESULT="PASS"
fi
# Org list
if echo "$org_list_response" | jq -e --arg id "$org_account_id" '.accounts[]? | select(.id == $id)' >/dev/null; then
  ORG_LIST_RESULT="PASS"
fi
# Org get
org_get_response=$(curl -sf -H "$AUTH_HEADER" -H "$CONTENT_TYPE" "$ACCOUNTS_API/$org_account_id?type=organization")
echo "$org_get_response" | jq .
if echo "$org_get_response" | jq -e --arg id "$org_account_id" '.id == $id' >/dev/null; then
  ORG_GET_RESULT="PASS"
fi
# Org update
org_update_response=$(curl -sf -X PUT \
  -H "$AUTH_HEADER" \
  -H "$CONTENT_TYPE" \
  -d "{\"id\": \"$org_account_id\", \"org_id\": \"$ORG_ID\", \"tenant_id\": \"$TENANT_UUID\", \"email\": \"updated-org-$TIMESTAMP@example.com\", \"status\": \"active\", \"currency\": \"EUR\"}" \
  "$ACCOUNTS_API/$org_account_id?type=organization")
echo "$org_update_response" | jq .
if echo "$org_update_response" | jq -e --arg email "updated-org-$TIMESTAMP@example.com" '.email == $email' >/dev/null; then
  ORG_UPDATE_RESULT="PASS"
fi
# Org delete
org_delete_response=$(curl -sf -X DELETE -H "$AUTH_HEADER" "$ACCOUNTS_API/$org_account_id?type=organization" -w "\nStatus: %{http_code}" || true)
echo "$org_delete_response"
if [[ "$org_delete_response" == *"Status: 204"* ]]; then
  ORG_DELETE_RESULT="PASS"
fi

# --- Print summary tables ---
print_header "Project Billing Account Endpoint Results"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint  | Create | List   | Get    | Update | Action | Delete |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Project   | $PROJECT_CREATE_RESULT   | $PROJECT_LIST_RESULT   | $PROJECT_GET_RESULT   | $PROJECT_UPDATE_RESULT   | $PROJECT_ACTION_RESULT   | $PROJECT_DELETE_RESULT   |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"

print_header "User Billing Account Endpoint Results"
echo -e "+-------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | Create | List   | Get    | Update | Delete |"
echo -e "+-------+--------+--------+--------+--------+--------+"
echo -e "| User  | $USER_CREATE_RESULT   | $USER_LIST_RESULT   | $USER_GET_RESULT   | $USER_UPDATE_RESULT   | $USER_DELETE_RESULT   |"
echo -e "+-------+--------+--------+--------+--------+--------+"

print_header "Organization Billing Account Endpoint Results"
echo -e "+--------------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint     | Create | List   | Get    | Update | Delete |"
echo -e "+--------------+--------+--------+--------+--------+--------+"
echo -e "| Organization | $ORG_CREATE_RESULT   | $ORG_LIST_RESULT   | $ORG_GET_RESULT   | $ORG_UPDATE_RESULT   | $ORG_DELETE_RESULT   |"
echo -e "+--------------+--------+--------+--------+--------+--------+"

print_header "Test Summary"
echo "- Organization ID: $ORG_ID"
echo "- Project ID: $PROJECT_ID"
echo "- Alt Project ID: $ALT_PROJECT_ID"
echo "- User ID: $USER_ID"

echo -e "\nTest Notes:"
echo "- Some 422 errors are expected due to foreign key constraints with test UUIDs."
echo "- Some errors are expected if database tables don't exist."
echo "- The important part is that the server handles all requests properly without crashes."

echo -e "\n${YELLOW}==== Migration Instructions ====\n${NC}"
echo "To create missing tables, run the database migrations:"
echo "  make migrate-up"
echo "Or manually execute the SQL migrations in the db/migrations directory." 