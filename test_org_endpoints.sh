#!/bin/bash

# Set your JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
API_URL="http://localhost:8080/api/v1"
OWNER_ID="afdb1105-daf2-4c14-91c8-4ad70bc2bfa7"

TIMESTAMP=$(date +%s)

# --- Track test results ---
LIST_RESULT="FAIL"
LIST_OWNER_RESULT="FAIL"
CREATE_RESULT="FAIL"
GET_RESULT="FAIL"
UPDATE_RESULT="FAIL"
GET_SETTINGS_RESULT="FAIL"
UPDATE_SETTINGS_RESULT="FAIL"
PAGINATE_RESULT="FAIL"
DELETE_RESULT="FAIL"

function print_header() {
  echo -e "\n==== $1 ====\n"
}

print_header "Testing GET /organizations endpoint"
LIST_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/organizations)
echo "$LIST_RESPONSE" | jq .
if echo "$LIST_RESPONSE" | jq -e '.[]' >/dev/null 2>&1; then
  LIST_RESULT="PASS"
fi

print_header "Testing GET /organizations?owner_id=XXX endpoint"
LIST_OWNER_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" "$API_URL/organizations?owner_id=$OWNER_ID")
echo "$LIST_OWNER_RESPONSE" | jq .
if echo "$LIST_OWNER_RESPONSE" | jq -e '.[]' >/dev/null 2>&1; then
  LIST_OWNER_RESULT="PASS"
fi

print_header "Testing POST /organizations endpoint"
ORG_RESPONSE=$(curl -sf -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Test Organization-$TIMESTAMP\",\"description\":\"A test organization\",\"owner_id\":\"$OWNER_ID\",\"status\":\"active\",\"max_projects\":10,\"tags\":{\"env\":\"development\",\"purpose\":\"testing\"}}" \
    $API_URL/organizations)
echo "Organization creation response: $ORG_RESPONSE"
ORG_ID=$(echo "$ORG_RESPONSE" | jq -r '.id // empty')
if [[ -n "$ORG_ID" && "$ORG_ID" != "null" ]]; then
  CREATE_RESULT="PASS"
else
  ORG_ID=$(uuidgen || echo "dfa8a7c6-1a6c-4a56-b9ce-466c354677e9")
  echo "Failed to extract org ID, using fallback ID: $ORG_ID"
fi

echo "Using Organization ID: $ORG_ID"

print_header "Testing GET /organizations/:id endpoint"
GET_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID)
echo "$GET_RESPONSE" | jq .
if echo "$GET_RESPONSE" | jq -e --arg id "$ORG_ID" '.id == $id' >/dev/null; then
  GET_RESULT="PASS"
fi

print_header "Testing PUT /organizations/:id endpoint"
UPDATE_RESPONSE=$(curl -sf -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"$ORG_ID\",\"name\":\"Updated Test Organization-$TIMESTAMP\",\"description\":\"This organization has been updated\",\"owner_id\":\"$OWNER_ID\",\"status\":\"active\",\"max_projects\":15,\"tags\":{\"env\":\"production\",\"purpose\":\"testing\"}}" \
    $API_URL/organizations/$ORG_ID)
echo "$UPDATE_RESPONSE" | jq .
if echo "$UPDATE_RESPONSE" | jq -e --arg name "Updated Test Organization-$TIMESTAMP" '.name == $name' >/dev/null; then
  UPDATE_RESULT="PASS"
fi

print_header "Testing GET /organizations/:id/settings endpoint"
GET_SETTINGS_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID/settings)
echo "$GET_SETTINGS_RESPONSE" | jq .
if echo "$GET_SETTINGS_RESPONSE" | jq -e '.' >/dev/null 2>&1; then
  GET_SETTINGS_RESULT="PASS"
fi

print_header "Testing PUT /organizations/:id/settings endpoint"
UPDATE_SETTINGS_RESPONSE=$(curl -sf -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"settings\":{\"feature_flags\":{\"new_dashboard\":true,\"beta_features\":false},\"billing_alerts\":{\"threshold\":5000,\"email_notifications\":true}}}" \
    $API_URL/organizations/$ORG_ID/settings)
echo "$UPDATE_SETTINGS_RESPONSE" | jq .
if echo "$UPDATE_SETTINGS_RESPONSE" | jq -e '.settings.feature_flags.new_dashboard == true' >/dev/null; then
  UPDATE_SETTINGS_RESULT="PASS"
fi

print_header "Testing GET /organizations endpoint with pagination"
PAGINATE_RESPONSE=$(curl -sf -H "Authorization: Bearer $TOKEN" "$API_URL/organizations?page=1&page_size=10&owner_id=$OWNER_ID")
echo "$PAGINATE_RESPONSE" | jq .
if echo "$PAGINATE_RESPONSE" | jq -e '.[]' >/dev/null 2>&1; then
  PAGINATE_RESULT="PASS"
fi

print_header "Testing DELETE /organizations/:id endpoint"
DELETE_RESPONSE=$(curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID -w "\nStatus: %{http_code}" || true)
echo "$DELETE_RESPONSE"
if [[ "$DELETE_RESPONSE" == *"Status: 204"* ]]; then
  DELETE_RESULT="PASS"
fi

# --- Print summary table ---
print_header "Organization Endpoint Results"
echo -e "+-------------------+--------+"
echo -e "| Endpoint          | Result |"
echo -e "+-------------------+--------+"
echo -e "| List              | $LIST_RESULT   |"
echo -e "| List by owner     | $LIST_OWNER_RESULT   |"
echo -e "| Create            | $CREATE_RESULT   |"
echo -e "| Get               | $GET_RESULT   |"
echo -e "| Update            | $UPDATE_RESULT   |"
echo -e "| Get settings      | $GET_SETTINGS_RESULT   |"
echo -e "| Update settings   | $UPDATE_SETTINGS_RESULT   |"
echo -e "| Paginate          | $PAGINATE_RESULT   |"
echo -e "| Delete            | $DELETE_RESULT   |"
echo -e "+-------------------+--------+"

print_header "Test Summary"
echo "- Organization ID: $ORG_ID"
echo "- Owner ID: $OWNER_ID"
echo -e "\nTest Notes:"
echo "- Some errors are expected if database tables don't exist."
echo "- The important part is that the server handles all requests properly without crashes." 