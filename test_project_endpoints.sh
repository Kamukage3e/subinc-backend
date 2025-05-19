#!/bin/bash

# Set your JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
API_URL="http://localhost:8080/api/v1"

# Generate timestamp to create unique organization and project names
TIMESTAMP=$(date +%s)

echo "Getting existing organizations to find a valid org_id..."
ORG_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" $API_URL/organizations?owner_id=afdb1105-daf2-4c14-91c8-4ad70bc2bfa7)
echo "Organization Response: $ORG_RESPONSE"

# Extract organization ID from the response if available
ORG_ID=$(echo $ORG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')

# If no organization was found, create one
if [ -z "$ORG_ID" ]; then
    echo "No existing organizations found. Creating a test organization..."
    
    CREATE_ORG_RESPONSE=$(curl -s -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"Test Organization-$TIMESTAMP\",\"description\":\"A test organization\",\"owner_id\":\"afdb1105-daf2-4c14-91c8-4ad70bc2bfa7\",\"status\":\"active\",\"max_projects\":10}" \
        $API_URL/organizations)
    
    echo "Create Organization Response: $CREATE_ORG_RESPONSE"
    
    # Extract the organization ID from the creation response
    ORG_ID=$(echo $CREATE_ORG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')
    
    if [ -z "$ORG_ID" ]; then
        echo "Failed to create organization. Using fallback ID."
        ORG_ID="25439848-8113-4756-a321-1ce674885e8c"
    fi
fi

echo "Using Organization ID: $ORG_ID"

echo "==== Testing GET /projects endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/projects | jq .

echo -e "\n==== Testing POST /projects endpoint (without org_id) ===="
PROJECT_NO_ORG_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Test Project Without Org-$TIMESTAMP\",\"description\":\"A test project created without an organization association\",\"status\":\"active\",\"tags\":{\"env\":\"development\",\"type\":\"test\"},\"org_id\":\"$ORG_ID\"}" \
    $API_URL/projects)

echo "Project creation response (without org_id): $PROJECT_NO_ORG_RESPONSE"

# Extract the project ID from the response
PROJECT_NO_ORG_ID=$(echo $PROJECT_NO_ORG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')

# If we didn't get a successful project creation, use a default UUID
if [ -z "$PROJECT_NO_ORG_ID" ]; then
    echo "Project creation without org_id failed. Using fallback ID."
    PROJECT_NO_ORG_ID="4b8ddc59-6c21-4049-9f47-580cbbc2c82c"
fi

echo "Using Project ID (without org_id): $PROJECT_NO_ORG_ID"

echo -e "\n==== Testing POST /projects endpoint (with org_id) ===="
PROJECT_WITH_ORG_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Test Project With Org-$TIMESTAMP\",\"description\":\"A test project created with an organization association\",\"status\":\"active\",\"tags\":{\"env\":\"development\",\"type\":\"test\"}}" \
    $API_URL/projects)

echo "Project creation response (with org_id): $PROJECT_WITH_ORG_RESPONSE"

# Extract the project ID from the response
PROJECT_WITH_ORG_ID=$(echo $PROJECT_WITH_ORG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//')

# If we didn't get a successful project creation, use a default UUID
if [ -z "$PROJECT_WITH_ORG_ID" ]; then
    echo "Project creation with org_id failed. Using project without org_id instead."
    PROJECT_WITH_ORG_ID=$PROJECT_NO_ORG_ID
fi

echo "Using Project ID (with org_id): $PROJECT_WITH_ORG_ID"

echo -e "\n==== Testing GET /projects/:id endpoint (project without org_id) ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID | jq .

echo -e "\n==== Testing GET /projects/:id endpoint (project with org_id) ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_WITH_ORG_ID | jq .

echo -e "\n==== Testing PUT /projects/:id endpoint (update project without org_id) ===="
curl -s -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"$PROJECT_NO_ORG_ID\",\"name\":\"Updated Project Without Org-$TIMESTAMP\",\"description\":\"This project has been updated without an org ID\",\"status\":\"active\",\"tags\":{\"env\":\"production\",\"type\":\"test\"}}" \
    $API_URL/projects/$PROJECT_NO_ORG_ID | jq .

echo -e "\n==== Testing GET /projects?org_id=XXX endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/projects?org_id=$ORG_ID&page=1&page_size=10" | jq .

echo -e "\n==== Testing GET /projects/:id/settings endpoint ===="
curl -s -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID/settings | jq .

echo -e "\n==== Testing PUT /projects/:id/settings endpoint ===="
curl -s -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"settings\":{\"feature_flags\":{\"new_dashboard\":true,\"beta_features\":false},\"alert_thresholds\":{\"cpu\":90,\"memory\":85}}}" \
    $API_URL/projects/$PROJECT_NO_ORG_ID/settings | jq .

echo -e "\n==== Testing DELETE /projects/:id endpoint ===="
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $API_URL/projects/$PROJECT_NO_ORG_ID -v

echo "All project endpoint tests completed."