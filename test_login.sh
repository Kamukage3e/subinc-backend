#!/bin/bash
set -e

API_URL="http://localhost:8080/api/v1"
EMAIL="admin@subinc.com"
PASSWORD="falc0nreaper!"

# Login and get access token
TOKEN=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -r .access_token)

if [[ "$TOKEN" == "null" || -z "$TOKEN" ]]; then
  echo "Login failed"
  exit 1
fi

echo "Access token: $TOKEN"

# Call /users/me with the token
curl -s -X GET "$API_URL/users/me" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" | jq .
