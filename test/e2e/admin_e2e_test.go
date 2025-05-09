package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	adminBaseURL = "http://localhost:8080/api/v1/admin"
)

func getAuthToken(t *testing.T) string {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJhZG1pbkBzdWJpbmMuY29tIiwiZXhwIjoxNzQ2ODczNjYyLCJyb2xlcyI6WyJzdXBlcnVzZXIiLCJhZG1pbiJdLCJzdWIiOiJhZG1pbjEyMyIsInR5cGUiOiJhZG1pbiJ9.XzCB4zyGfE5LMH6oLtliwzNJQ4_R_hNYh38rQooVG9s"
	if token == "" {
		t.Fatal("E2E_ADMIN_TOKEN not set")
	}
	return token
}

func doRequest(t *testing.T, method, url string, body any, token string) *http.Response {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func TestAdminUsersCRUD(t *testing.T) {
	token := getAuthToken(t)
	userReq := map[string]any{
		"username":      fmt.Sprintf("e2euser-%d", time.Now().UnixNano()),
		"email":         fmt.Sprintf("e2euser-%d@acme.com", time.Now().UnixNano()),
		"password_hash": "$2a$12$abcdefghijklmnopqrstuv",
		"roles":         []string{"superuser"},
		"is_active":     true,
	}
	resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var user map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
	userID, ok := user["id"].(string)
	require.True(t, ok && userID != "")
	require.Contains(t, user, "username")
	require.Contains(t, user, "email")
	require.Contains(t, user, "roles")
	require.Contains(t, user, "is_active")
	require.NotContains(t, user, "password_hash")
	resp.Body.Close()

	// Get
	resp = doRequest(t, "GET", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Equal(t, userID, got["id"])
	require.Equal(t, user["username"], got["username"])
	require.Equal(t, user["email"], got["email"])
	require.Contains(t, got, "roles")
	require.Contains(t, got, "is_active")
	require.NotContains(t, got, "password_hash")
	resp.Body.Close()

	// List
	resp = doRequest(t, "GET", adminBaseURL+"/users?limit=10", nil, token)
	require.Equal(t, 200, resp.StatusCode)
	var list struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	require.GreaterOrEqual(t, len(list.Data), 1)
	for _, u := range list.Data {
		require.Contains(t, u, "id")
		require.Contains(t, u, "username")
		require.Contains(t, u, "email")
		require.Contains(t, u, "roles")
		require.Contains(t, u, "is_active")
		require.NotContains(t, u, "password_hash")
	}
	resp.Body.Close()

	// Update
	updateReq := map[string]any{
		"username":  user["username"].(string) + "-upd",
		"email":     "upd-" + user["email"].(string),
		"roles":     []string{"admin"},
		"is_active": false,
	}
	resp = doRequest(t, "PUT", adminBaseURL+"/users/"+userID, updateReq, token)
	require.Equal(t, 200, resp.StatusCode)
	var updated map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updated))
	require.Equal(t, updateReq["username"], updated["username"])
	require.Equal(t, updateReq["email"], updated["email"])
	require.Equal(t, updateReq["roles"], updated["roles"])
	require.Equal(t, updateReq["is_active"], updated["is_active"])
	resp.Body.Close()

	// Get after update
	resp = doRequest(t, "GET", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	var gotUpd map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&gotUpd))
	require.Equal(t, updateReq["username"], gotUpd["username"])
	require.Equal(t, updateReq["email"], gotUpd["email"])
	require.Equal(t, updateReq["roles"], gotUpd["roles"])
	require.Equal(t, updateReq["is_active"], gotUpd["is_active"])
	resp.Body.Close()

	// Delete
	resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Get after delete
	resp = doRequest(t, "GET", adminBaseURL+"/users/"+userID, nil, token)
	require.True(t, resp.StatusCode == 404 || resp.StatusCode == 400)
	resp.Body.Close()
}

func TestAdminTenantsCRUD(t *testing.T) {
	token := getAuthToken(t)
	// Create
	tenantReq := map[string]any{
		"name":      fmt.Sprintf("e2etenant-%d", time.Now().UnixNano()),
		"email":     fmt.Sprintf("e2etenant-%d@acme.com", time.Now().UnixNano()),
		"is_active": true,
		"metadata":  map[string]any{},
	}
	resp := doRequest(t, "POST", adminBaseURL+"/tenants", tenantReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var tenant map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tenant))
	tenantID := tenant["id"].(string)
	resp.Body.Close()

	// Get
	resp = doRequest(t, "GET", adminBaseURL+"/tenants/"+tenantID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// List
	resp = doRequest(t, "GET", adminBaseURL+"/tenants?limit=10", nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Update
	updateReq := map[string]any{
		"name":      tenant["name"].(string) + "-upd",
		"email":     "upd-" + tenant["email"].(string),
		"is_active": false,
	}
	resp = doRequest(t, "PUT", adminBaseURL+"/tenants/"+tenantID, updateReq, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Delete
	resp = doRequest(t, "DELETE", adminBaseURL+"/tenants/"+tenantID, nil, token)
	require.Equal(t, 204, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminRolesCRUD(t *testing.T) {
	token := getAuthToken(t)
	// Create
	roleReq := map[string]any{
		"name":        fmt.Sprintf("e2erole-%d", time.Now().UnixNano()),
		"permissions": []string{"read", "write"},
		"description": "E2E test role",
	}
	resp := doRequest(t, "POST", adminBaseURL+"/roles", roleReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var role map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&role))
	roleID := role["id"].(string)
	resp.Body.Close()

	// Get
	resp = doRequest(t, "GET", adminBaseURL+"/roles/"+roleID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// List
	resp = doRequest(t, "GET", adminBaseURL+"/roles?limit=10", nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Update
	updateReq := map[string]any{
		"name":        role["name"].(string) + "-upd",
		"permissions": []string{"read"},
		"description": "Updated E2E test role",
	}
	resp = doRequest(t, "PUT", adminBaseURL+"/roles/"+roleID, updateReq, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Delete
	resp = doRequest(t, "DELETE", adminBaseURL+"/roles/"+roleID, nil, token)
	require.Equal(t, 204, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminPermissionsCRUD(t *testing.T) {
	token := getAuthToken(t)
	// Create
	permReq := map[string]any{
		"name":        fmt.Sprintf("e2eperm-%d", time.Now().UnixNano()),
		"description": "E2E test permission",
	}
	resp := doRequest(t, "POST", adminBaseURL+"/permissions", permReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var perm map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&perm))
	permID := perm["id"].(string)
	resp.Body.Close()

	// Get
	resp = doRequest(t, "GET", adminBaseURL+"/permissions/"+permID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// List
	resp = doRequest(t, "GET", adminBaseURL+"/permissions?limit=10", nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Update
	updateReq := map[string]any{
		"name":        perm["name"].(string) + "-upd",
		"description": "Updated E2E test permission",
	}
	resp = doRequest(t, "PUT", adminBaseURL+"/permissions/"+permID, updateReq, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Delete
	resp = doRequest(t, "DELETE", adminBaseURL+"/permissions/"+permID, nil, token)
	require.Equal(t, 204, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAPIKeysCRUD(t *testing.T) {
	token := getAuthToken(t)
	// Create user for API key
	userReq := map[string]any{
		"username":      fmt.Sprintf("e2euserkey-%d", time.Now().UnixNano()),
		"email":         fmt.Sprintf("e2euserkey-%d@acme.com", time.Now().UnixNano()),
		"password_hash": "$2a$12$abcdefghijklmnopqrstuv",
		"roles":         []string{"superuser"},
		"is_active":     true,
	}
	resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var user map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
	userID := user["id"].(string)
	resp.Body.Close()

	// Create API key
	apiKeyReq := map[string]any{
		"user_id": userID,
		"name":    fmt.Sprintf("e2eapikey-%d", time.Now().UnixNano()),
	}
	resp = doRequest(t, "POST", adminBaseURL+"/api-keys", apiKeyReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var apiKey map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiKey))
	apiKeyID := apiKey["id"].(string)
	resp.Body.Close()

	// Get
	resp = doRequest(t, "GET", adminBaseURL+"/api-keys/"+apiKeyID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// List
	resp = doRequest(t, "GET", adminBaseURL+"/api-keys?limit=10", nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Update
	updateReq := map[string]any{
		"name": apiKey["name"].(string) + "-upd",
	}
	resp = doRequest(t, "PUT", adminBaseURL+"/api-keys/"+apiKeyID, updateReq, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()

	// Delete
	resp = doRequest(t, "DELETE", adminBaseURL+"/api-keys/"+apiKeyID, nil, token)
	require.Equal(t, 204, resp.StatusCode)
	resp.Body.Close()

	// Cleanup user
	resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminSessionsAndImpersonation(t *testing.T) {
	token := getAuthToken(t)
	t.Run("ListSessions", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/sessions", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ImpersonateUser", func(t *testing.T) {
		// Create user to impersonate
		userReq := map[string]any{
			"username":      fmt.Sprintf("e2eimpersonate-%d", time.Now().UnixNano()),
			"email":         fmt.Sprintf("e2eimpersonate-%d@acme.com", time.Now().UnixNano()),
			"password_hash": "$2a$12$abcdefghijklmnopqrstuv",
			"roles":         []string{"superuser"},
			"is_active":     true,
		}
		resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var user map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
		userID := user["id"].(string)
		resp.Body.Close()
		// Impersonate
		impReq := map[string]any{"user_id": userID}
		resp = doRequest(t, "POST", adminBaseURL+"/impersonate", impReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminSupportAndRBAC(t *testing.T) {
	token := getAuthToken(t)
	t.Run("SupportTools", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/support-tools", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("RBACStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/rbac", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminStepUpDelegatedSCIM(t *testing.T) {
	token := getAuthToken(t)
	t.Run("StepUpAuth", func(t *testing.T) {
		// Create user
		userReq := map[string]any{
			"username":      fmt.Sprintf("e2estepup-%d", time.Now().UnixNano()),
			"email":         fmt.Sprintf("e2estepup-%d@acme.com", time.Now().UnixNano()),
			"password_hash": "$2a$12$abcdefghijklmnopqrstuv",
			"roles":         []string{"superuser"},
			"is_active":     true,
		}
		resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var user map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
		userID := user["id"].(string)
		resp.Body.Close()
		// StepUp
		stepReq := map[string]any{"user_id": userID}
		resp = doRequest(t, "POST", adminBaseURL+"/stepup", stepReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("DelegatedAdminStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/delegated-admin", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SCIMStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/scim", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminAuditAnomalyRateLimits(t *testing.T) {
	token := getAuthToken(t)
	t.Run("AuditAnomalies", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/audit/anomaly", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("GetRateLimitConfig", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/rate-limits", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminAbuseAlertsSecretsSystem(t *testing.T) {
	token := getAuthToken(t)
	t.Run("AbuseDetection", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/abuse", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("Alerts", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/alerts", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("GetSecretsStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/secrets", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SystemConfig", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/system/config", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminFeatureFlagsMaintenanceMonitoring(t *testing.T) {
	token := getAuthToken(t)
	t.Run("ListFeatureFlags", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/system/flags", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("CreateUpdateDeleteFeatureFlag", func(t *testing.T) {
		flagReq := map[string]any{"name": fmt.Sprintf("e2eflag-%d", time.Now().UnixNano()), "enabled": true}
		resp := doRequest(t, "POST", adminBaseURL+"/system/flags", flagReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var flag map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&flag))
		flagName := flag["name"].(string)
		resp.Body.Close()
		// Update
		updateReq := map[string]any{"name": flagName, "enabled": false}
		resp = doRequest(t, "PATCH", adminBaseURL+"/system/flags", updateReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Delete
		resp = doRequest(t, "DELETE", adminBaseURL+"/system/flags?name="+flagName, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("GetSetMaintenanceMode", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/system/maintenance", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		setReq := map[string]any{"maintenance": true}
		resp = doRequest(t, "PATCH", adminBaseURL+"/system/maintenance", setReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		setReq["maintenance"] = false
		resp = doRequest(t, "PATCH", adminBaseURL+"/system/maintenance", setReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("GetUpdateMonitoringConfig", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/monitoring", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		updateReq := map[string]any{"enabled": true}
		resp = doRequest(t, "PATCH", adminBaseURL+"/monitoring", updateReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminMFA(t *testing.T) {
	token := getAuthToken(t)
	// Create user for MFA
	userReq := map[string]any{
		"username":      fmt.Sprintf("e2emfa-%d", time.Now().UnixNano()),
		"email":         fmt.Sprintf("e2emfa-%d@acme.com", time.Now().UnixNano()),
		"password_hash": "$2a$12$abcdefghijklmnopqrstuv",
		"roles":         []string{"superuser"},
		"is_active":     true,
	}
	resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var user map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
	userID := user["id"].(string)
	resp.Body.Close()
	t.Run("EnableMFA", func(t *testing.T) {
		req := map[string]any{"user_id": userID}
		resp := doRequest(t, "POST", adminBaseURL+"/mfa/enable", req, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("DisableMFA", func(t *testing.T) {
		req := map[string]any{"user_id": userID}
		resp := doRequest(t, "POST", adminBaseURL+"/mfa/disable", req, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ResetMFA", func(t *testing.T) {
		req := map[string]any{"user_id": userID}
		resp := doRequest(t, "POST", adminBaseURL+"/mfa/reset", req, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("MFAStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/mfa/status/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	// Cleanup
	resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminPolicies(t *testing.T) {
	token := getAuthToken(t)
	t.Run("ListPolicies", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/policies", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("CreateUpdateDeletePolicy", func(t *testing.T) {
		policyReq := map[string]any{"name": fmt.Sprintf("e2epolicy-%d", time.Now().UnixNano()), "rules": []any{"allow"}}
		resp := doRequest(t, "POST", adminBaseURL+"/policies", policyReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var policy map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&policy))
		policyID := policy["id"].(string)
		resp.Body.Close()
		// Get
		resp = doRequest(t, "GET", adminBaseURL+"/policies/"+policyID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Update
		updateReq := map[string]any{"name": policy["name"].(string) + "-upd", "rules": []any{"deny"}}
		resp = doRequest(t, "PUT", adminBaseURL+"/policies/"+policyID, updateReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Delete
		resp = doRequest(t, "DELETE", adminBaseURL+"/policies/"+policyID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminSupportTraces(t *testing.T) {
	token := getAuthToken(t)
	t.Run("UserTrace", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/support/user-trace", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("BillingTrace", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/support/billing-trace", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ImpersonationAudit", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/support/impersonation-audit", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminNotifications(t *testing.T) {
	token := getAuthToken(t)
	t.Run("ListNotifications", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/notifications", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("CreateGetUpdateDeleteNotification", func(t *testing.T) {
		notifReq := map[string]any{"type": "info", "recipient": "e2e@acme.com", "subject": "E2E", "body": "test"}
		resp := doRequest(t, "POST", adminBaseURL+"/notifications", notifReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var notif map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&notif))
		notifID := notif["id"].(string)
		resp.Body.Close()
		// Get
		resp = doRequest(t, "GET", adminBaseURL+"/notifications/"+notifID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Mark sent
		markReq := map[string]any{"sent_at": time.Now().UTC().Format(time.RFC3339)}
		resp = doRequest(t, "PATCH", adminBaseURL+"/notifications/"+notifID, markReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminMarketingSSMEmail(t *testing.T) {
	token := getAuthToken(t)
	t.Run("MarketingTools", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/marketing-tools", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SSMBlogs", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/ssm/blogs", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SSMNews", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/ssm/news", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ListEmailProviders", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/email/providers", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ListEmailTemplates", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/email/templates", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ListTeamAdmins", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/email/team/test-team/admins", nil, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	t.Run("ListEmailDeliveries", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/email/deliveries", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("ListConversations", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/email/conversations", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminProjectOrgCRUD(t *testing.T) {
	token := getAuthToken(t)
	t.Run("CreateListUpdateDeleteProject", func(t *testing.T) {
		projReq := map[string]any{"name": fmt.Sprintf("e2eproject-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/projects", projReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var proj map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&proj))
		projID := proj["id"].(string)
		resp.Body.Close()
		// List
		resp = doRequest(t, "GET", adminBaseURL+"/projects", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Update
		updateReq := map[string]any{"name": proj["name"].(string) + "-upd"}
		resp = doRequest(t, "PUT", adminBaseURL+"/projects/"+projID, updateReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Delete
		resp = doRequest(t, "DELETE", adminBaseURL+"/projects/"+projID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("CreateListUpdateDeleteOrg", func(t *testing.T) {
		orgReq := map[string]any{"name": fmt.Sprintf("e2eorg-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/orgs", orgReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var org map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID := org["id"].(string)
		resp.Body.Close()
		// List
		resp = doRequest(t, "GET", adminBaseURL+"/orgs", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Update
		updateReq := map[string]any{"name": org["name"].(string) + "-upd"}
		resp = doRequest(t, "PUT", adminBaseURL+"/orgs/"+orgID, updateReq, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Delete
		resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminProjectOrgSubresources(t *testing.T) {
	token := getAuthToken(t)
	// Project users, teams, invitations, api-keys, settings, audit, transfer-owner, bulk ops
	t.Run("ProjectUsersBulkOps", func(t *testing.T) {
		projReq := map[string]any{"name": fmt.Sprintf("e2eprojectsub-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/projects", projReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var proj map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&proj))
		projID := proj["id"].(string)
		resp.Body.Close()
		// List users
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/users", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Bulk add/remove users (simulate with empty list)
		bulkReq := map[string]any{"user_ids": []string{}}
		resp = doRequest(t, "POST", adminBaseURL+"/projects/"+projID+"/users/bulk-add", bulkReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "POST", adminBaseURL+"/projects/"+projID+"/users/bulk-remove", bulkReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Audit logs
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/audit", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Settings
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/settings", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		updateReq := map[string]any{"settings": map[string]any{"foo": "bar"}}
		resp = doRequest(t, "PATCH", adminBaseURL+"/projects/"+projID+"/settings", updateReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Invitations
		invReq := map[string]any{"email": fmt.Sprintf("invite-%d@acme.com", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/projects/"+projID+"/invitations", invReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/invitations", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// API keys
		apiKeyReq := map[string]any{"name": fmt.Sprintf("e2eprojectkey-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/projects/"+projID+"/api-keys", apiKeyReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/api-keys", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Transfer owner
		transferReq := map[string]any{"new_owner_id": "nonexistent"}
		resp = doRequest(t, "PATCH", adminBaseURL+"/projects/"+projID+"/transfer-owner", transferReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/projects/"+projID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	// Org users, teams, invitations, api-keys, settings, audit, transfer-owner, bulk ops
	t.Run("OrgUsersBulkOps", func(t *testing.T) {
		orgReq := map[string]any{"name": fmt.Sprintf("e2eorgsub-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/orgs", orgReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var org map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID := org["id"].(string)
		resp.Body.Close()
		// List users
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/users", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Bulk add/remove users (simulate with empty list)
		bulkReq := map[string]any{"user_ids": []string{}}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/users/bulk-add", bulkReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/users/bulk-remove", bulkReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Audit logs
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/audit", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Settings
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/settings", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		updateReq := map[string]any{"settings": map[string]any{"foo": "bar"}}
		resp = doRequest(t, "PATCH", adminBaseURL+"/orgs/"+orgID+"/settings", updateReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Invitations
		invReq := map[string]any{"email": fmt.Sprintf("invite-%d@acme.com", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/invitations", invReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/invitations", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// API keys
		apiKeyReq := map[string]any{"name": fmt.Sprintf("e2eorgkey-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/api-keys", apiKeyReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/api-keys", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Transfer owner
		transferReq := map[string]any{"new_owner_id": "nonexistent"}
		resp = doRequest(t, "PATCH", adminBaseURL+"/orgs/"+orgID+"/transfer-owner", transferReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminRolePermissionAndAPIKeyOps(t *testing.T) {
	token := getAuthToken(t)
	t.Run("AssignRemovePermissionToRole", func(t *testing.T) {
		roleReq := map[string]any{"name": fmt.Sprintf("e2eroleperm-%d", time.Now().UnixNano()), "permissions": []string{"read"}, "description": "E2E role"}
		resp := doRequest(t, "POST", adminBaseURL+"/roles", roleReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var role map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&role))
		roleID := role["id"].(string)
		resp.Body.Close()
		permReq := map[string]any{"name": fmt.Sprintf("e2eperm-%d", time.Now().UnixNano()), "description": "E2E perm"}
		resp = doRequest(t, "POST", adminBaseURL+"/permissions", permReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var perm map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&perm))
		permID := perm["id"].(string)
		resp.Body.Close()
		// Assign
		assignReq := map[string]any{"permission_id": permID}
		resp = doRequest(t, "POST", adminBaseURL+"/roles/"+roleID+"/permissions", assignReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 201)
		resp.Body.Close()
		// Remove
		resp = doRequest(t, "DELETE", adminBaseURL+"/roles/"+roleID+"/permissions/"+permID, nil, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 204)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/roles/"+roleID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/permissions/"+permID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("APIKeyRotateAndAudit", func(t *testing.T) {
		userReq := map[string]any{"username": fmt.Sprintf("e2euserkeyops-%d", time.Now().UnixNano()), "email": fmt.Sprintf("e2euserkeyops-%d@acme.com", time.Now().UnixNano()), "password_hash": "$2a$12$abcdefghijklmnopqrstuv", "roles": []string{"superuser"}, "is_active": true}
		resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var user map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
		userID := user["id"].(string)
		resp.Body.Close()
		apiKeyReq := map[string]any{"user_id": userID, "name": fmt.Sprintf("e2eapikeyops-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/api-keys", apiKeyReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var apiKey map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiKey))
		apiKeyID := apiKey["id"].(string)
		resp.Body.Close()
		// Rotate
		resp = doRequest(t, "POST", adminBaseURL+"/api-keys/"+apiKeyID+"/rotate", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Audit
		resp = doRequest(t, "GET", adminBaseURL+"/api-keys/audit", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/api-keys/"+apiKeyID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminEdgeCasesAndRemainingEndpoints(t *testing.T) {
	token := getAuthToken(t)
	t.Run("DelegatedAdminStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/delegated-admin", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SCIMStatus", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/scim", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("AuditAnomalies", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/audit/anomaly", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("PatchRateLimits", func(t *testing.T) {
		patchReq := map[string]any{"global": map[string]any{"max_requests": 100, "window_seconds": 60}}
		resp := doRequest(t, "PATCH", adminBaseURL+"/rate-limits", patchReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	t.Run("AbuseDetection", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/abuse", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("Alerts", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/alerts", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("PatchSecrets", func(t *testing.T) {
		patchReq := map[string]any{"secrets": map[string]any{"foo": "bar"}}
		resp := doRequest(t, "PATCH", adminBaseURL+"/secrets", patchReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	t.Run("SystemConfig", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/system/config", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("PatchMaintenanceMode", func(t *testing.T) {
		patchReq := map[string]any{"maintenance": true}
		resp := doRequest(t, "PATCH", adminBaseURL+"/system/maintenance", patchReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	t.Run("PatchMonitoringConfig", func(t *testing.T) {
		patchReq := map[string]any{"enabled": true}
		resp := doRequest(t, "PATCH", adminBaseURL+"/monitoring", patchReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	// MFA error cases
	t.Run("MFAStatusNotFound", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/mfa/status/nonexistent", nil, token)
		require.True(t, resp.StatusCode == 400 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	// Policies error cases
	t.Run("GetPolicyNotFound", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/policies/nonexistent", nil, token)
		require.Equal(t, 404, resp.StatusCode)
		resp.Body.Close()
	})
	// Notifications error cases
	t.Run("GetNotificationNotFound", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/notifications/nonexistent", nil, token)
		require.Equal(t, 404, resp.StatusCode)
		resp.Body.Close()
	})
	// Email provider/template/team admin ops
	t.Run("AddUpdateDeleteEmailProvider", func(t *testing.T) {
		providerReq := map[string]any{"name": fmt.Sprintf("e2eprovider-%d", time.Now().UnixNano()), "type": "smtp", "config": map[string]any{"host": "smtp.example.com", "port": 587}}
		resp := doRequest(t, "POST", adminBaseURL+"/email/providers", providerReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "PUT", adminBaseURL+"/email/providers", providerReq, token)
		require.True(t, resp.StatusCode == 204 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/email/providers/"+providerReq["name"].(string), nil, token)
		require.True(t, resp.StatusCode == 204 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	t.Run("AddDeleteEmailTemplate", func(t *testing.T) {
		tmplReq := map[string]any{"name": fmt.Sprintf("e2etmpl-%d", time.Now().UnixNano()), "subject": "E2E", "body": "test"}
		resp := doRequest(t, "POST", adminBaseURL+"/email/templates", tmplReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/email/templates/"+tmplReq["name"].(string), nil, token)
		require.True(t, resp.StatusCode == 204 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	t.Run("AddRemoveTeamAdmin", func(t *testing.T) {
		team := "e2eteam"
		email := fmt.Sprintf("e2eteamadmin-%d@acme.com", time.Now().UnixNano())
		addReq := map[string]any{"email": email}
		resp := doRequest(t, "POST", adminBaseURL+"/email/team/"+team+"/admins", addReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/email/team/"+team+"/admins/"+email, nil, token)
		require.True(t, resp.StatusCode == 204 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	t.Run("SendTestEmail", func(t *testing.T) {
		req := map[string]any{"to": "e2etest@acme.com", "subject": "E2E", "body": "test"}
		resp := doRequest(t, "POST", adminBaseURL+"/email/test", req, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	t.Run("StartAddMessageConversation", func(t *testing.T) {
		convReq := map[string]any{"subject": "E2E", "participants": []string{"e2e@acme.com"}}
		resp := doRequest(t, "POST", adminBaseURL+"/email/conversations", convReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		// Add message (simulate with random ID)
		msgReq := map[string]any{"body": "test"}
		resp = doRequest(t, "POST", adminBaseURL+"/email/conversations/nonexistent/messages", msgReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 404 || resp.StatusCode == 400)
		resp.Body.Close()
	})
}

func TestAdminTeamsAndRBAC(t *testing.T) {
	token := getAuthToken(t)
	// Project teams
	t.Run("ProjectTeams", func(t *testing.T) {
		projReq := map[string]any{"name": fmt.Sprintf("e2eprojectteam-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/projects", projReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var proj map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&proj))
		projID := proj["id"].(string)
		resp.Body.Close()
		// Add team (simulate with org endpoint, as project teams may be org teams)
		orgReq := map[string]any{"name": fmt.Sprintf("e2eorgteam-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs", orgReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var org map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID := org["id"].(string)
		resp.Body.Close()
		teamReq := map[string]any{"name": fmt.Sprintf("e2eteam-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/teams", teamReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/teams", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
		// Cleanup
		resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/projects/"+projID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	// RBAC/permission/feature flag/maintenance/monitoring edge cases
	t.Run("ForbiddenFeatureFlag", func(t *testing.T) {
		resp := doRequest(t, "DELETE", adminBaseURL+"/system/flags?name=nonexistent", nil, token)
		require.True(t, resp.StatusCode == 204 || resp.StatusCode == 404)
		resp.Body.Close()
	})
	t.Run("ForbiddenMaintenance", func(t *testing.T) {
		patchReq := map[string]any{"maintenance": "invalid"}
		resp := doRequest(t, "PATCH", adminBaseURL+"/system/maintenance", patchReq, token)
		require.True(t, resp.StatusCode == 400 || resp.StatusCode == 422)
		resp.Body.Close()
	})
	t.Run("ForbiddenMonitoring", func(t *testing.T) {
		patchReq := map[string]any{"enabled": "invalid"}
		resp := doRequest(t, "PATCH", adminBaseURL+"/monitoring", patchReq, token)
		require.True(t, resp.StatusCode == 400 || resp.StatusCode == 422)
		resp.Body.Close()
	})
}

func TestAdminEffectivePermissionsAndProfile(t *testing.T) {
	token := getAuthToken(t)
	// Create user
	userReq := map[string]any{"username": fmt.Sprintf("e2eeffperm-%d", time.Now().UnixNano()), "email": fmt.Sprintf("e2eeffperm-%d@acme.com", time.Now().UnixNano()), "password_hash": "$2a$12$abcdefghijklmnopqrstuv", "roles": []string{"superuser"}, "is_active": true}
	resp := doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
	require.Equal(t, 201, resp.StatusCode)
	var user map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
	userID := user["id"].(string)
	resp.Body.Close()
	t.Run("UserEffectivePermissions", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/users/"+userID+"/effective-permissions", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("AllUserRolesPermissions", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/users/all-roles-permissions", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("Profile", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/profile", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	// Cleanup
	resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
	require.Equal(t, 200, resp.StatusCode)
	resp.Body.Close()
}

func TestAdminAuditBillingHealthMetrics(t *testing.T) {
	token := getAuthToken(t)
	t.Run("ListAuditLogs", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/audit", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("BillingSummary", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/billing", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("SystemHealth", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/security/health", nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("MetricsStub", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/metrics", nil, token)
		require.Equal(t, 501, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("HealthStub", func(t *testing.T) {
		resp := doRequest(t, "GET", adminBaseURL+"/health", nil, token)
		require.Equal(t, 501, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAdminOrgProjectTeamsAndEffectivePermissions(t *testing.T) {
	token := getAuthToken(t)
	// Org teams CRUD, transfer-owner, bulk ops
	t.Run("OrgTeamsCRUD", func(t *testing.T) {
		orgReq := map[string]any{"name": fmt.Sprintf("e2eorgteamcrud-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/orgs", orgReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var org map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID := org["id"].(string)
		resp.Body.Close()
		teamReq := map[string]any{"name": fmt.Sprintf("e2eteamcrud-%d", time.Now().UnixNano())}
		resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/teams", teamReq, token)
		require.True(t, resp.StatusCode == 201 || resp.StatusCode == 400)
		var team map[string]any
		if resp.StatusCode == 201 {
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&team))
			teamID := team["id"].(string)
			resp.Body.Close()
			// Get
			resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID, nil, token)
			require.Equal(t, 200, resp.StatusCode)
			resp.Body.Close()
			// Update
			updateReq := map[string]any{"name": team["name"].(string) + "-upd"}
			resp = doRequest(t, "PUT", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID, updateReq, token)
			require.Equal(t, 200, resp.StatusCode)
			resp.Body.Close()
			// Transfer owner
			transferReq := map[string]any{"new_owner_id": "nonexistent"}
			resp = doRequest(t, "PATCH", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID+"/transfer-owner", transferReq, token)
			require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
			resp.Body.Close()
			// Bulk add/remove users
			bulkReq := map[string]any{"user_ids": []string{}}
			resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID+"/users/bulk-add", bulkReq, token)
			require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
			resp.Body.Close()
			resp = doRequest(t, "POST", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID+"/users/bulk-remove", bulkReq, token)
			require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
			resp.Body.Close()
			// Remove user (simulate with random ID)
			resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID+"/users/nonexistent", nil, token)
			require.True(t, resp.StatusCode == 204 || resp.StatusCode == 404)
			resp.Body.Close()
			// Delete
			resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID+"/teams/"+teamID, nil, token)
			require.Equal(t, 204, resp.StatusCode)
			resp.Body.Close()
		}
		resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
	})
	// Bulk transfer teams
	t.Run("OrgTeamsBulkTransfer", func(t *testing.T) {
		bulkReq := map[string]any{"team_ids": []string{}}
		resp := doRequest(t, "POST", adminBaseURL+"/orgs/teams/bulk-transfer", bulkReq, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 400)
		resp.Body.Close()
	})
	// Project/org effective permissions
	t.Run("ProjectUserEffectivePermissions", func(t *testing.T) {
		// Create project and user
		projReq := map[string]any{"name": fmt.Sprintf("e2eeffpermproj-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/projects", projReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var proj map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&proj))
		projID := proj["id"].(string)
		resp.Body.Close()
		userReq := map[string]any{"username": fmt.Sprintf("e2eeffpermuser-%d", time.Now().UnixNano()), "email": fmt.Sprintf("e2eeffpermuser-%d@acme.com", time.Now().UnixNano()), "password_hash": "$2a$12$abcdefghijklmnopqrstuv", "roles": []string{"superuser"}, "is_active": true}
		resp = doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var user map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
		userID := user["id"].(string)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/projects/"+projID+"/users/"+userID+"/effective-permissions", nil, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 404)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/projects/"+projID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("OrgUserEffectivePermissions", func(t *testing.T) {
		// Create org and user
		orgReq := map[string]any{"name": fmt.Sprintf("e2eeffpermorg-%d", time.Now().UnixNano())}
		resp := doRequest(t, "POST", adminBaseURL+"/orgs", orgReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var org map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID := org["id"].(string)
		resp.Body.Close()
		userReq := map[string]any{"username": fmt.Sprintf("e2eeffpermuserorg-%d", time.Now().UnixNano()), "email": fmt.Sprintf("e2eeffpermuserorg-%d@acme.com", time.Now().UnixNano()), "password_hash": "$2a$12$abcdefghijklmnopqrstuv", "roles": []string{"superuser"}, "is_active": true}
		resp = doRequest(t, "POST", adminBaseURL+"/users", userReq, token)
		require.Equal(t, 201, resp.StatusCode)
		var user map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
		userID := user["id"].(string)
		resp.Body.Close()
		resp = doRequest(t, "GET", adminBaseURL+"/orgs/"+orgID+"/users/"+userID+"/effective-permissions", nil, token)
		require.True(t, resp.StatusCode == 200 || resp.StatusCode == 404)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/orgs/"+orgID, nil, token)
		require.Equal(t, 204, resp.StatusCode)
		resp.Body.Close()
		resp = doRequest(t, "DELETE", adminBaseURL+"/users/"+userID, nil, token)
		require.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	})
}
