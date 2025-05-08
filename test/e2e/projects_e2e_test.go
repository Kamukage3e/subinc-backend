package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

const (
	projectsBaseURL    = "http://localhost:8080/api/v1/admin/projects"
	projectsAuthHeader = "Authorization"
)

func getProjectsAdminToken() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJhZG1pbkBzdWJpbmMuY29tIiwiZXhwIjoxNzQ2ODAzNzU3LCJyb2xlcyI6WyJzdXBlcnVzZXIiLCJhZG1pbiJdLCJzdWIiOiJhZG1pbjEyMyIsInR5cGUiOiJhZG1pbiJ9.JyPhaMYBV3y82RyPchjlumJ-rafjhpXnoRq401tVQzQ"
}

func TestProjectsE2E(t *testing.T) {
	token := getProjectsAdminToken()

	// 1. Create project
	projectReq := map[string]interface{}{
		"name":        "E2E Project",
		"description": "E2E Project Desc",
		"owner_id":    "admin-uuid",
	}
	projectBody, _ := json.Marshal(projectReq)
	resp, err := http.Post(projectsBaseURL, "application/json", bytes.NewReader(projectBody))
	if err != nil {
		t.Fatalf("create project failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var project map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&project)
	projectID, ok := project["id"].(string)
	if !ok || projectID == "" {
		t.Fatal("project id missing in response")
	}

	// 2. List projects
	req, _ := http.NewRequest(http.MethodGet, projectsBaseURL, nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list projects failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var listResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&listResp)
	projs, ok := listResp["projects"].([]interface{})
	if !ok || len(projs) == 0 {
		t.Fatal("no projects returned")
	}

	// 3. Get project
	req, _ = http.NewRequest(http.MethodGet, projectsBaseURL+"/"+projectID, nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get project failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var getResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&getResp)
	if getResp["id"] != projectID {
		t.Fatalf("project id mismatch: %v", getResp["id"])
	}

	// 4. Update project
	updateReq := map[string]interface{}{"name": "E2E Project Updated"}
	updateBody, _ := json.Marshal(updateReq)
	req, _ = http.NewRequest(http.MethodPut, projectsBaseURL+"/"+projectID, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update project failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var updateResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&updateResp)
	if updateResp["name"] != "E2E Project Updated" {
		t.Fatalf("project name not updated: %v", updateResp["name"])
	}

	// 5. Project audit logs
	req, _ = http.NewRequest(http.MethodGet, projectsBaseURL+"/"+projectID+"/audit", nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("project audit logs failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 6. Project settings
	req, _ = http.NewRequest(http.MethodGet, projectsBaseURL+"/"+projectID+"/settings", nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get project settings failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 7. Update project settings
	settingsReq := map[string]interface{}{"key": "value"}
	settingsBody, _ := json.Marshal(settingsReq)
	req, _ = http.NewRequest(http.MethodPatch, projectsBaseURL+"/"+projectID+"/settings", bytes.NewReader(settingsBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("update project settings failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 8. Create project API key
	apiKeyReq := map[string]interface{}{"name": "e2e-key"}
	apiKeyBody, _ := json.Marshal(apiKeyReq)
	req, _ = http.NewRequest(http.MethodPost, projectsBaseURL+"/"+projectID+"/api-keys", bytes.NewReader(apiKeyBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create project api key failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var apiKey map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&apiKey)
	if apiKey["name"] != "e2e-key" {
		t.Fatalf("api key name mismatch: %v", apiKey["name"])
	}

	// 9. List project API keys
	req, _ = http.NewRequest(http.MethodGet, projectsBaseURL+"/"+projectID+"/api-keys", nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list project api keys failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// 10. Delete project
	req, _ = http.NewRequest(http.MethodDelete, projectsBaseURL+"/"+projectID, nil)
	req.Header.Set(projectsAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete project failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}
