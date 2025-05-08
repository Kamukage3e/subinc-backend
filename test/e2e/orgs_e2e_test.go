package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const baseURL = "http://localhost:8080/api/v1/admin/orgs"
const loginURL = "http://localhost:8080/api/v1/login"

func waitForServer(t *testing.T) {
	for i := 0; i < 30; i++ {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode < 500 {
			return
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("server not ready after 30s")
}

func loginAndGetToken(t *testing.T) string {
	payload := map[string]interface{}{"username": "admin@subinc.com", "password": "admin123"}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(loginURL, "application/json", bytes.NewReader(body))
	fmt.Println(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var res map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
	token, ok := res["token"].(string)
	require.True(t, ok)
	return token
}

func authRequest(method, url, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func buildURL(base string, elems ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	for _, e := range elems {
		u.Path = path.Join(u.Path, e)
	}
	return u.String()
}

func TestOrgsE2E(t *testing.T) {
	waitForServer(t)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJhZG1pbkBzdWJpbmMuY29tIiwiZXhwIjoxNzQ2ODAzNzU3LCJyb2xlcyI6WyJzdXBlcnVzZXIiLCJhZG1pbiJdLCJzdWIiOiJhZG1pbjEyMyIsInR5cGUiOiJhZG1pbiJ9.JyPhaMYBV3y82RyPchjlumJ-rafjhpXnoRq401tVQzQ"
	fmt.Println(token)
	var orgID, teamID string

	t.Run("CreateOrg - success", func(t *testing.T) {
		payload := map[string]interface{}{"name": "E2E Org"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPost, baseURL, token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var org map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		orgID = org["id"].(string)
	})

	t.Run("ListOrgs - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, baseURL, token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var res map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&res))
		orgs, ok := res["organizations"].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, orgs)
	})

	t.Run("GetOrg - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var org map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		require.Equal(t, orgID, org["id"])
	})

	t.Run("UpdateOrg - success", func(t *testing.T) {
		payload := map[string]interface{}{"name": "E2E Org Updated"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPut, buildURL(baseURL, orgID), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var org map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&org))
		require.Equal(t, "E2E Org Updated", org["name"])
	})

	t.Run("OrgAuditLogs - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "audit"), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetOrgSettings - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "settings"), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("UpdateOrgSettings - success", func(t *testing.T) {
		payload := map[string]interface{}{"key": "value"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPatch, buildURL(baseURL, orgID, "settings"), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("InviteOrgUser - success", func(t *testing.T) {
		payload := map[string]interface{}{"email": "e2euser@example.com", "role": "member"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPost, buildURL(baseURL, orgID, "invitations"), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var invitation map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&invitation))
	})

	t.Run("ListOrgInvitations - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "invitations"), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("CreateOrgAPIKey - success", func(t *testing.T) {
		payload := map[string]interface{}{"name": "e2e-key"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPost, buildURL(baseURL, orgID, "api-keys"), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var apiKey map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&apiKey))
	})

	t.Run("ListOrgAPIKeys - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "api-keys"), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("CreateOrgTeam - success", func(t *testing.T) {
		payload := map[string]interface{}{"name": "E2E Team"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPost, buildURL(baseURL, orgID, "teams"), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var team map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&team))
		teamID = team["id"].(string)
	})

	t.Run("ListOrgTeams - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "teams"), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetOrgTeam - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodGet, buildURL(baseURL, orgID, "teams", teamID), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("UpdateOrgTeam - success", func(t *testing.T) {
		payload := map[string]interface{}{"name": "E2E Team Updated"}
		body, _ := json.Marshal(payload)
		resp, err := authRequest(http.MethodPut, buildURL(baseURL, orgID, "teams", teamID), token, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("DeleteOrgTeam - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodDelete, buildURL(baseURL, orgID, "teams", teamID), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("DeleteOrg - success", func(t *testing.T) {
		resp, err := authRequest(http.MethodDelete, buildURL(baseURL, orgID), token, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	})
}
