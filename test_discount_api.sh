#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# --- Color Codes ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# --- Auth and API config ---
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRoX3Byb3ZpZGVyIjoiZGVmYXVsdCIsImNyZWF0ZWRfYXQiOiIyMDI1LTA1LTEzVDE1OjQ4OjE1LjYxNjYzMiswNTowMCIsImRldmljZSI6ImN1cmwvOC43LjEiLCJlbWFpbCI6ImFkbWluQHN1YmluYy5jb20iLCJleHAiOjE3NDc3MTQ1NjgsImlhdCI6MTc0NzYyODE2OCwiaWQiOiJhZmRiMTEwNS1kYWYyLTRjMTQtOTFjOC00YWQ3MGJjMmJmYTciLCJpcCI6IjEyNy4wLjAuMSIsImlzcyI6InN1YmluYy1iYWNrZW5kIiwibGFzdF9hY3Rpdml0eSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzkxWiIsImxvZ2luX21ldGhvZCI6InBhc3N3b3JkIiwibG9naW5fdGltZSI6IjIwMjUtMDUtMTlUMDQ6MTY6MDguMDEyNzg3WiIsInNlY3VyaXR5X21ldGFkYXRhIjp7ImF1dGhlbnRpY2F0ZWQiOnRydWUsImlwX2FkZHJlc3MiOiIxMjcuMC4wLjEiLCJsb2dpbl9tZXRob2QiOiJwYXNzd29yZCIsImxvZ2luX3RpbWUiOiIyMDI1LTA1LTE5VDA0OjE2OjA4LjAxMjc5NVoiLCJ1c2VyX2FnZW50IjoiY3VybC84LjcuMSJ9LCJ0ZW5hbnRfaWQiOiIiLCJ0b2tlbl90eXBlIjoiYWNjZXNzIiwidXNlcl9pZCI6ImFmZGIxMTA1LWRhZjItNGMxNC05MWM4LTRhZDcwYmMyYmZhNyIsInVzZXJfc3RhdHVzIjoiIn0.HSCfws1JcZ-vPQ65wTeirKZkcCQgwtTV9MogJQJfcHY"
AUTH_HEADER="Authorization: Bearer $TOKEN"
CONTENT_TYPE="Content-Type: application/json"
API_URL="http://localhost:8080/api/v1/billing-management"

ORG_ID="617d3910-e193-4701-9e1b-27a671acc848"

# --- Helpers ---
function print_header() {
  echo -e "\n${YELLOW}==== $1 ====\n${NC}"
}

function extract_id() {
  local json="$1"
  local id
  id=$(echo "$json" | jq -r '.id // empty')
  if [[ -z "$id" || "$id" == "null" ]]; then
    id=""
  fi
  echo "$id"
}

function print_status() {
  local name="$1"
  local result="$2"
  if [[ "$result" == "PASS" ]]; then
    echo -e "  - $name: ${GREEN}PASS${NC}"
  elif [[ "$result" == "SKIP" ]]; then
    echo -e "  - $name: ${YELLOW}SKIP${NC}"
  else
    echo -e "  - $name: ${RED}FAIL${NC}"
  fi
}

# --- Result Vars ---
DISCOUNT_CREATE_RESULT="FAIL"
DISCOUNT_LIST_RESULT="FAIL"
DISCOUNT_GET_RESULT="FAIL"
DISCOUNT_UPDATE_RESULT="FAIL"
DISCOUNT_GET_BY_CODE_RESULT="FAIL"
DISCOUNT_DELETE_RESULT="FAIL"

COUPON_CREATE_RESULT="FAIL"
COUPON_LIST_RESULT="FAIL"
COUPON_GET_RESULT="FAIL"
COUPON_UPDATE_RESULT="FAIL"
COUPON_GET_BY_CODE_RESULT="FAIL"
COUPON_REDEEM_RESULT="FAIL"
COUPON_DELETE_RESULT="FAIL"

CREDIT_CREATE_RESULT="FAIL"
CREDIT_LIST_RESULT="FAIL"
CREDIT_GET_RESULT="FAIL"
CREDIT_UPDATE_RESULT="FAIL"
CREDIT_PATCH_RESULT="FAIL"
CREDIT_APPLY_RESULT="FAIL"
CREDIT_DELETE_RESULT="FAIL"

PLUGIN_LIST_RESULT="FAIL"
PLUGIN_GET_RESULT="SKIP"
PLUGIN_CONFIGURE_RESULT="SKIP"
PLUGIN_DISABLE_RESULT="SKIP"

# --- Setup: Use existing org for coupon tests ---
# Set this to a real org UUID from your DB
ORG_ID="REPLACE_WITH_REAL_ORG_UUID"
if [[ -z "$ORG_ID" || "$ORG_ID" == "null" ]]; then
  echo -e "${RED}ORG_ID is not set. Set ORG_ID to a valid organization UUID at the top of the script.${NC}"
  COUPON_CREATE_RESULT="SKIP"
  COUPON_LIST_RESULT="SKIP"
  COUPON_GET_RESULT="SKIP"
  COUPON_UPDATE_RESULT="SKIP"
  COUPON_GET_BY_CODE_RESULT="SKIP"
  COUPON_REDEEM_RESULT="SKIP"
  COUPON_DELETE_RESULT="SKIP"
  CREDIT_CREATE_RESULT="SKIP"
  CREDIT_LIST_RESULT="SKIP"
  CREDIT_GET_RESULT="SKIP"
  CREDIT_UPDATE_RESULT="SKIP"
  CREDIT_PATCH_RESULT="SKIP"
  CREDIT_APPLY_RESULT="SKIP"
  CREDIT_DELETE_RESULT="SKIP"
else

# --- DISCOUNT ---
print_header "DISCOUNT CRUD"
DISCOUNT_CODE="test-$(date +%s)"
DISCOUNT_ID=""
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/discounts" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"code":"'$DISCOUNT_CODE'","type":"percentage","value":10,"max_redemptions":5,"redeemed":0,"start_at":"2024-01-01T00:00:00Z","end_at":"2025-01-01T00:00:00Z","is_active":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
body=$(echo "$resp" | sed '$d')
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "201" ]]; then
  DISCOUNT_ID=$(extract_id "$body")
  if [[ -n "$DISCOUNT_ID" ]]; then
    DISCOUNT_CREATE_RESULT="PASS"
  fi
else
  echo -e "${RED}Discount create failed: $body${NC}"
fi

resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts" -H "$AUTH_HEADER")
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "200" ]]; then
  DISCOUNT_LIST_RESULT="PASS"
fi

resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/$DISCOUNT_ID" -H "$AUTH_HEADER")
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "200" ]]; then
  DISCOUNT_GET_RESULT="PASS"
fi

resp=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/discounts/$DISCOUNT_ID" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"code":"'$DISCOUNT_CODE'","type":"fixed","value":5,"max_redemptions":10,"redeemed":1,"start_at":"2024-01-01T00:00:00Z","end_at":"2025-01-01T00:00:00Z","is_active":false,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "200" ]]; then
  DISCOUNT_UPDATE_RESULT="PASS"
fi

resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/code/$DISCOUNT_CODE" -H "$AUTH_HEADER")
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "200" ]]; then
  DISCOUNT_GET_BY_CODE_RESULT="PASS"
fi

# --- COUPON ---
print_header "COUPON CRUD"
COUPON_CODE="coupon-$(date +%s)"
COUPON_ID=""
if [[ "$DISCOUNT_CREATE_RESULT" != "PASS" || -z "$DISCOUNT_ID" || -z "$ORG_ID" ]]; then
  echo -e "${YELLOW}Skipping coupon tests: discount creation failed or missing DISCOUNT_ID/ORG_ID${NC}"
  COUPON_CREATE_RESULT="SKIP"
  COUPON_LIST_RESULT="SKIP"
  COUPON_GET_RESULT="SKIP"
  COUPON_UPDATE_RESULT="SKIP"
  COUPON_GET_BY_CODE_RESULT="SKIP"
  COUPON_REDEEM_RESULT="SKIP"
  COUPON_DELETE_RESULT="SKIP"
else
  resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/discounts/coupons" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"code":"'$COUPON_CODE'","discount_id":"'$DISCOUNT_ID'","org_id":"'$ORG_ID'","max_redemptions":3,"redeemed":0,"start_at":"2024-01-01T00:00:00Z","end_at":"2025-01-01T00:00:00Z","is_active":true,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "201" ]]; then
    COUPON_ID=$(extract_id "$body")
    if [[ -n "$COUPON_ID" ]]; then
      COUPON_CREATE_RESULT="PASS"
    fi
  else
    echo -e "${RED}Coupon create failed: $body${NC}"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/coupons" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    COUPON_LIST_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/coupons/$COUPON_ID" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    COUPON_GET_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/discounts/coupons/$COUPON_ID" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"code":"'$COUPON_CODE'","discount_id":"'$DISCOUNT_ID'","org_id":"'$ORG_ID'","max_redemptions":5,"redeemed":2,"start_at":"2024-01-01T00:00:00Z","end_at":"2025-01-01T00:00:00Z","is_active":false,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    COUPON_UPDATE_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/coupons/code/$COUPON_CODE" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    COUPON_GET_BY_CODE_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/discounts/coupons/$COUPON_ID/redeem" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{}')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    COUPON_REDEEM_RESULT="PASS"
  fi
fi

# --- CREDIT ---
print_header "CREDIT CRUD"
CREDIT_ID=""
ACCOUNT_ID="acct-$(date +%s)"
if [[ "$CREDIT_CREATE_RESULT" != "PASS" && "$COUPON_CREATE_RESULT" != "PASS" ]]; then
  # Only skip if both are missing, otherwise try to create credit
  if [[ "$COUPON_CREATE_RESULT" != "PASS" ]]; then
    echo -e "${YELLOW}Skipping credit tests: coupon creation failed or missing COUPON_ID${NC}"
  else
    echo -e "${YELLOW}Skipping credit tests: credit creation failed or missing ACCOUNT_ID${NC}"
  fi
  CREDIT_CREATE_RESULT="SKIP"
  CREDIT_LIST_RESULT="SKIP"
  CREDIT_GET_RESULT="SKIP"
  CREDIT_UPDATE_RESULT="SKIP"
  CREDIT_PATCH_RESULT="SKIP"
  CREDIT_APPLY_RESULT="SKIP"
  CREDIT_DELETE_RESULT="SKIP"
else
  resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/discounts/credits" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"account_id":"'$ACCOUNT_ID'","amount":100,"currency":"USD","type":"account","status":"active","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
  body=$(echo "$resp" | sed '$d')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "201" ]]; then
    CREDIT_ID=$(extract_id "$body")
    if [[ -n "$CREDIT_ID" ]]; then
      CREDIT_CREATE_RESULT="PASS"
    fi
  else
    echo -e "${RED}Credit create failed: $body${NC}"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/credits" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    CREDIT_LIST_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/discounts/credits/$CREDIT_ID" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    CREDIT_GET_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/discounts/credits/$CREDIT_ID" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"account_id":"'$ACCOUNT_ID'","amount":200,"currency":"USD","type":"account","status":"active","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","metadata":"{}"}')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    CREDIT_UPDATE_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/discounts/credits/$CREDIT_ID" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"status":"consumed"}')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    CREDIT_PATCH_RESULT="PASS"
  fi
  resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/discounts/credits/$CREDIT_ID/apply" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"invoice_id":"inv-$(date +%s)"}')
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "200" ]]; then
    CREDIT_APPLY_RESULT="PASS"
  fi
fi

# --- PLUGIN ---
print_header "PLUGIN ENDPOINTS"
resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/plugins/discount" -H "$AUTH_HEADER")
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "200" ]]; then
  PLUGIN_LIST_RESULT="PASS"
  plugin_json=$(echo "$resp" | sed '$d')
  # Only extract PLUGIN_NAME if plugin_json is a valid array
  if echo "$plugin_json" | jq -e 'type == "array"' >/dev/null 2>&1; then
    PLUGIN_NAME=$(echo "$plugin_json" | jq -r '.[0].name // empty')
  else
    PLUGIN_NAME=""
  fi
  if [[ -n "$PLUGIN_NAME" ]]; then
    resp=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/plugins/discount/$PLUGIN_NAME" -H "$AUTH_HEADER")
    code=$(echo "$resp" | tail -n1)
    if [[ "$code" == "200" ]]; then
      PLUGIN_GET_RESULT="PASS"
    fi
    resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/plugins/discount/$PLUGIN_NAME/configure" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{"config":{}}')
    code=$(echo "$resp" | tail -n1)
    if [[ "$code" == "200" ]]; then
      PLUGIN_CONFIGURE_RESULT="PASS"
    fi
    resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/plugins/discount/$PLUGIN_NAME/disable" -H "$AUTH_HEADER" -H "$CONTENT_TYPE" -d '{}')
    code=$(echo "$resp" | tail -n1)
    if [[ "$code" == "200" ]]; then
      PLUGIN_DISABLE_RESULT="PASS"
    fi
  else
    PLUGIN_GET_RESULT="SKIP"
    PLUGIN_CONFIGURE_RESULT="SKIP"
    PLUGIN_DISABLE_RESULT="SKIP"
  fi
else
  PLUGIN_LIST_RESULT="FAIL"
  PLUGIN_GET_RESULT="SKIP"
  PLUGIN_CONFIGURE_RESULT="SKIP"
  PLUGIN_DISABLE_RESULT="SKIP"
fi

# --- CLEANUP ---
print_header "CLEANUP"
if [[ -n "$CREDIT_ID" ]]; then
  resp=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/discounts/credits/$CREDIT_ID" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "204" ]]; then
    CREDIT_DELETE_RESULT="PASS"
  fi
else
  echo -e "${YELLOW}Skipping credit delete: CREDIT_ID is empty${NC}"
  CREDIT_DELETE_RESULT="SKIP"
fi
if [[ -n "$COUPON_ID" ]]; then
  resp=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/discounts/coupons/$COUPON_ID" -H "$AUTH_HEADER")
  code=$(echo "$resp" | tail -n1)
  if [[ "$code" == "204" ]]; then
    COUPON_DELETE_RESULT="PASS"
  fi
else
  echo -e "${YELLOW}Skipping coupon delete: COUPON_ID is empty${NC}"
  COUPON_DELETE_RESULT="SKIP"
fi
resp=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/discounts/$DISCOUNT_ID" -H "$AUTH_HEADER")
code=$(echo "$resp" | tail -n1)
if [[ "$code" == "204" ]]; then
  DISCOUNT_DELETE_RESULT="PASS"
fi

# --- SUMMARY TABLES ---
print_header "Discount Endpoint Results"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint  | Create | List   | Get    | Update | GetByCode | Delete |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Discount  | $DISCOUNT_CREATE_RESULT   | $DISCOUNT_LIST_RESULT   | $DISCOUNT_GET_RESULT   | $DISCOUNT_UPDATE_RESULT   | $DISCOUNT_GET_BY_CODE_RESULT   | $DISCOUNT_DELETE_RESULT   |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | Create | List   | Get    | Update | GetByCode | Redeem | Delete |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Coupon  | $COUPON_CREATE_RESULT   | $COUPON_LIST_RESULT   | $COUPON_GET_RESULT   | $COUPON_UPDATE_RESULT   | $COUPON_GET_BY_CODE_RESULT   | $COUPON_REDEEM_RESULT   | $COUPON_DELETE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | Create | List   | Get    | Update | Patch  | Apply  | Delete |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Credit  | $CREDIT_CREATE_RESULT   | $CREDIT_LIST_RESULT   | $CREDIT_GET_RESULT   | $CREDIT_UPDATE_RESULT   | $CREDIT_PATCH_RESULT   | $CREDIT_APPLY_RESULT   | $CREDIT_DELETE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | List   | Get    | Configure | Disable |"
echo -e "+--------+--------+--------+--------+--------+"
echo -e "| Plugin  | $PLUGIN_LIST_RESULT   | $PLUGIN_GET_RESULT   | $PLUGIN_CONFIGURE_RESULT   | $PLUGIN_DISABLE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+"

print_header "Test Notes"
echo "- Some errors may be expected if required foreign keys or plugins are missing."
echo "- The important part is that the server handles all requests properly without crashes."
echo -e "\n${YELLOW}==== Migration Instructions ====\n${NC}"
echo "To create missing tables, run the database migrations:"
echo "  make migrate-up"
echo "Or manually execute the SQL migrations in the db/migrations directory."
fi

# --- SUMMARY TABLES ---
print_header "Discount Endpoint Results"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint  | Create | List   | Get    | Update | GetByCode | Delete |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"
echo -e "| Discount  | $DISCOUNT_CREATE_RESULT   | $DISCOUNT_LIST_RESULT   | $DISCOUNT_GET_RESULT   | $DISCOUNT_UPDATE_RESULT   | $DISCOUNT_GET_BY_CODE_RESULT   | $DISCOUNT_DELETE_RESULT   |"
echo -e "+-----------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | Create | List   | Get    | Update | GetByCode | Redeem | Delete |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Coupon  | $COUPON_CREATE_RESULT   | $COUPON_LIST_RESULT   | $COUPON_GET_RESULT   | $COUPON_UPDATE_RESULT   | $COUPON_GET_BY_CODE_RESULT   | $COUPON_REDEEM_RESULT   | $COUPON_DELETE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | Create | List   | Get    | Update | Patch  | Apply  | Delete |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"
echo -e "| Credit  | $CREDIT_CREATE_RESULT   | $CREDIT_LIST_RESULT   | $CREDIT_GET_RESULT   | $CREDIT_UPDATE_RESULT   | $CREDIT_PATCH_RESULT   | $CREDIT_APPLY_RESULT   | $CREDIT_DELETE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+--------+--------+--------+"

echo -e "+--------+--------+--------+--------+--------+"
echo -e "| Endpoint | List   | Get    | Configure | Disable |"
echo -e "+--------+--------+--------+--------+--------+"
echo -e "| Plugin  | $PLUGIN_LIST_RESULT   | $PLUGIN_GET_RESULT   | $PLUGIN_CONFIGURE_RESULT   | $PLUGIN_DISABLE_RESULT   |"
echo -e "+--------+--------+--------+--------+--------+"

print_header "Test Notes"
echo "- Some errors may be expected if required foreign keys or plugins are missing."
echo "- The important part is that the server handles all requests properly without crashes."
echo -e "\n${YELLOW}==== Migration Instructions ====\n${NC}"
echo "To create missing tables, run the database migrations:"
echo "  make migrate-up"
echo "Or manually execute the SQL migrations in the db/migrations directory." 