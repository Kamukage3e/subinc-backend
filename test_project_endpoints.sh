#!/bin/bash

# Set your JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
API_URL="http://localhost:8080/api/v1"
OWNER_ID="afdb1105-daf2-4c14-91c8-4ad70bc2bfa7"

TIMESTAMP=$(date +%s)

# --- Track test results ---
LIST_RESULT="FAIL"
CREATE_NO_ORG_RESULT="FAIL"
CREATE_WITH_ORG_RESULT="FAIL"
GET_NO_ORG_RESULT="FAIL"
GET_WITH_ORG_RESULT="FAIL"
UPDATE_RESULT="FAIL"
LIST_BY_ORG_RESULT="FAIL"
GET_SETTINGS_RESULT="FAIL"
UPDATE_SETTINGS_RESULT="FAIL"
DELETE_RESULT="FAIL"

function print_header() {
  echo -e "\n==== $1 ====\n"
}

print_header "Getting existing organizations to find a valid org_id..."
ORG_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" "$API_URL/organizations?owner_id=$OWNER_ID")
echo "Organization Response: $ORG_RESPONSE"
ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.organizations[0].id // empty')
if [ -z "$ORG_ID" ]; then
  print_header "No existing organizations found. Creating a test organization..."
  CREATE_ORG_RESPONSE=$(curl -sf -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Test Organization-$TIMESTAMP\",\"description\":\"A test organization\",\"owner_id\":\"$OWNER_ID\",\"status\":\"active\",\"max_projects\":10}" \
    $API_URL/organizations)
  echo "Create Organization Response: $CREATE_ORG_RESPONSE"
  ORG_ID=$(echo "$CREATE_ORG_RESPONSE" | jq -r '.id // empty')
  if [ -z "$ORG_ID" ]; then
    echo "Failed to create organization. Using fallback ID."
    ORG_ID="25439848-8113-4756-a321-1ce674885e8c"
  fi
fi

echo "Using Organization ID: $ORG_ID"

print_header "Testing GET /projects endpoint"
LIST_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/projects)
echo "$LIST_RESPONSE" | jq .
if echo "$LIST_RESPONSE" | jq -e '.projects // .[]' >/dev/null 2>&1; then
  LIST_RESULT="PASS"
fi

print_header "Testing POST /projects endpoint (without org_id)"
PROJECT_NO_ORG_RESPONSE=$(curl -sf -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Test Project Without Org-$TIMESTAMP\",\"description\":\"A test project created without an organization association\",\"status\":\"active\",\"tags\":{\"env\":\"development\",\"type\":\"test\"}}" \
  $API_URL/projects)
echo "Project creation response (without org_id): $PROJECT_NO_ORG_RESPONSE"
PROJECT_NO_ORG_ID=$(echo "$PROJECT_NO_ORG_RESPONSE" | jq -r '.id // empty')
if [ -n "$PROJECT_NO_ORG_ID" ]; then
  CREATE_NO_ORG_RESULT="PASS"
else
  PROJECT_NO_ORG_ID="4b8ddc59-6c21-4049-9f47-580cbbc2c82c"
fi

echo "Using Project ID (without org_id): $PROJECT_NO_ORG_ID"

print_header "Testing POST /projects endpoint (with org_id)"
PROJECT_WITH_ORG_RESPONSE=$(curl -sf -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Test Project With Org-$TIMESTAMP\",\"description\":\"A test project created with an organization association\",\"status\":\"active\",\"tags\":{\"env\":\"development\",\"type\":\"test\"}}" \
  $API_URL/projects)
echo "Project creation response (with org_id): $PROJECT_WITH_ORG_RESPONSE"
PROJECT_WITH_ORG_ID=$(echo "$PROJECT_WITH_ORG_RESPONSE" | jq -r '.id // empty')
if [ -n "$PROJECT_WITH_ORG_ID" ]; then
  CREATE_WITH_ORG_RESULT="PASS"
else
  PROJECT_WITH_ORG_ID="$PROJECT_NO_ORG_ID"
fi

echo "Using Project ID (with org_id): $PROJECT_WITH_ORG_ID"

print_header "Testing GET /projects/:id endpoint (project without org_id)"
GET_NO_ORG_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID)
echo "$GET_NO_ORG_RESPONSE" | jq .
if echo "$GET_NO_ORG_RESPONSE" | jq -e --arg id "$PROJECT_NO_ORG_ID" '.id == $id' >/dev/null; then
  GET_NO_ORG_RESULT="PASS"
fi

print_header "Testing GET /projects/:id endpoint (project with org_id)"
GET_WITH_ORG_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_WITH_ORG_ID)
echo "$GET_WITH_ORG_RESPONSE" | jq .
if echo "$GET_WITH_ORG_RESPONSE" | jq -e --arg id "$PROJECT_WITH_ORG_ID" '.id == $id' >/dev/null; then
  GET_WITH_ORG_RESULT="PASS"
fi

print_header "Testing PUT /projects/:id endpoint (update project without org_id)"
UPDATE_RESPONSE=$(curl -sf -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"id\":\"$PROJECT_NO_ORG_ID\",\"name\":\"Updated Project Without Org-$TIMESTAMP\",\"description\":\"This project has been updated without an org ID\",\"status\":\"active\",\"tags\":{\"env\":\"production\",\"type\":\"test\"}}" \
  $API_URL/projects/$PROJECT_NO_ORG_ID)
echo "$UPDATE_RESPONSE" | jq .
if echo "$UPDATE_RESPONSE" | jq -e --arg name "Updated Project Without Org-$TIMESTAMP" '.name == $name' >/dev/null; then
  UPDATE_RESULT="PASS"
fi

print_header "Testing GET /projects?org_id=XXX endpoint"
LIST_BY_ORG_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" "$API_URL/projects?org_id=$ORG_ID&page=1&page_size=10")
echo "$LIST_BY_ORG_RESPONSE" | jq .
if echo "$LIST_BY_ORG_RESPONSE" | jq -e '.projects // .[]' >/dev/null 2>&1; then
  LIST_BY_ORG_RESULT="PASS"
fi

print_header "Testing GET /projects/:id/settings endpoint"
GET_SETTINGS_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID/settings)
echo "$GET_SETTINGS_RESPONSE" | jq .
if echo "$GET_SETTINGS_RESPONSE" | jq -e '.settings' >/dev/null 2>&1; then
  GET_SETTINGS_RESULT="PASS"
fi

print_header "Testing PUT /projects/:id/settings endpoint"
UPDATE_SETTINGS_RESPONSE=$(curl -sf -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"settings\":{\"feature_flags\":{\"new_dashboard\":true,\"beta_features\":false},\"alert_thresholds\":{\"cpu\":90,\"memory\":85}}}" \
  $API_URL/projects/$PROJECT_NO_ORG_ID/settings)
echo "$UPDATE_SETTINGS_RESPONSE" | jq .
if echo "$UPDATE_SETTINGS_RESPONSE" | jq -e '.settings.feature_flags.new_dashboard == true' >/dev/null; then
  UPDATE_SETTINGS_RESULT="PASS"
fi

print_header "Testing DELETE /projects/:id endpoint"
DELETE_RESPONSE=$(curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID -w "\nStatus: %{http_code}" || true)
echo "$DELETE_RESPONSE"
if [[ "$DELETE_RESPONSE" == *"Status: 204"* ]]; then
  DELETE_RESULT="PASS"
fi

# --- Print summary table ---
print_header "Project Endpoint Results"
echo -e "+-------------------+--------+"
echo -e "| Endpoint          | Result |"
echo -e "+-------------------+--------+"
echo -e "| List              | $LIST_RESULT   |"
echo -e "| Create w/o org    | $CREATE_NO_ORG_RESULT   |"
echo -e "| Create w/ org     | $CREATE_WITH_ORG_RESULT   |"
echo -e "| Get (no org)      | $GET_NO_ORG_RESULT   |"
echo -e "| Get (with org)    | $GET_WITH_ORG_RESULT   |"
echo -e "| Update            | $UPDATE_RESULT   |"
echo -e "| List by org       | $LIST_BY_ORG_RESULT   |"
echo -e "| Get settings      | $GET_SETTINGS_RESULT   |"
echo -e "| Update settings   | $UPDATE_SETTINGS_RESULT   |"
echo -e "| Delete            | $DELETE_RESULT   |"
echo -e "+-------------------+--------+"

print_header "Test Summary"
echo "- Organization ID: $ORG_ID"
echo "- Project ID (no org): $PROJECT_NO_ORG_ID"
echo "- Project ID (with org): $PROJECT_WITH_ORG_ID"
echo -e "\nTest Notes:"
echo "- Some errors are expected if database tables don't exist."
echo "- The important part is that the server handles all requests properly without crashes."