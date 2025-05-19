#!/bin/bash

# Set your JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
API_URL="http://localhost:8080/api/v1"

# Generate timestamp for unique organization name
TIMESTAMP=$(date +%s)

echo "==== Testing GET /organizations endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/organizations | jq .

echo -e "\n==== Testing GET /organizations?owner_id=XXX endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/organizations?owner_id=afdb1105-daf2-4c14-91c8-4ad70bc2bfa7 | jq .

echo -e "\n==== Testing POST /organizations endpoint ===="
ORG_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Test Organization-$TIMESTAMP\",\"description\":\"A test organization\",\"owner_id\":\"afdb1105-daf2-4c14-91c8-4ad70bc2bfa7\",\"status\":\"active\",\"max_projects\":10,\"tags\":{\"env\":\"development\",\"purpose\":\"testing\"}}" \
    $API_URL/organizations)

echo "Organization creation response: $ORG_RESPONSE"

# Extract the organization ID from the response
ORG_ID=$(echo $ORG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')

# If no organization was created, use a UUID pattern
if [ -z "$ORG_ID" ]; then
    # Generate a random UUID if extraction failed
    ORG_ID=$(uuidgen || echo "dfa8a7c6-1a6c-4a56-b9ce-466c354677e9")
    echo "Failed to extract org ID, using fallback ID: $ORG_ID"
fi

echo "Using Organization ID: $ORG_ID"

echo -e "\n==== Testing GET /organizations/:id endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID | jq .

echo -e "\n==== Testing PUT /organizations/:id endpoint ===="
curl -s -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"$ORG_ID\",\"name\":\"Updated Test Organization-$TIMESTAMP\",\"description\":\"This organization has been updated\",\"owner_id\":\"afdb1105-daf2-4c14-91c8-4ad70bc2bfa7\",\"status\":\"active\",\"max_projects\":15,\"tags\":{\"env\":\"production\",\"purpose\":\"testing\"}}" \
    $API_URL/organizations/$ORG_ID | jq .

echo -e "\n==== Testing GET /organizations/:id/settings endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID/settings | jq .

echo -e "\n==== Testing PUT /organizations/:id/settings endpoint ===="
curl -s -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"settings\":{\"feature_flags\":{\"new_dashboard\":true,\"beta_features\":false},\"billing_alerts\":{\"threshold\":5000,\"email_notifications\":true}}}" \
    $API_URL/organizations/$ORG_ID/settings | jq .

echo -e "\n==== Testing GET /organizations endpoint with pagination ===="
curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/organizations?page=1&page_size=10&owner_id=afdb1105-daf2-4c14-91c8-4ad70bc2bfa7" | jq .

echo -e "\n==== Testing DELETE /organizations/:id endpoint ===="
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $API_URL/organizations/$ORG_ID -v

echo "All organization endpoint tests completed." 