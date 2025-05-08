package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

const (
	projectBaseURL  = "http://localhost:8080/api/v1/admin"
	adminAuthHeader = "Authorization"
)

func getAdminToken() string {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJhZG1pbkBzdWJpbmMuY29tIiwiZXhwIjoxNzQ2ODAzNzU3LCJyb2xlcyI6WyJzdXBlcnVzZXIiLCJhZG1pbiJdLCJzdWIiOiJhZG1pbjEyMyIsInR5cGUiOiJhZG1pbiJ9.JyPhaMYBV3y82RyPchjlumJ-rafjhpXnoRq401tVQzQ"
	return token
}

func TestProjectInvitationsE2E(t *testing.T) {
	token := getAdminToken()

	// 1. Create a project
	projectReq := map[string]interface{}{
		"name":        "E2E Project",
		"description": "E2E Project Desc",
		"owner_id":    "admin-uuid",
	}
	projectBody, _ := json.Marshal(projectReq)
	resp, err := http.Post(projectBaseURL+"/projects", "application/json", bytes.NewReader(projectBody))
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

	// 2. Invite a user
	inviteReq := map[string]interface{}{
		"email": "invitee@e2e.com",
		"role":  "member",
	}
	inviteBody, _ := json.Marshal(inviteReq)
	req, _ := http.NewRequest(http.MethodPost, projectBaseURL+"/projects/"+projectID+"/invitations", bytes.NewReader(inviteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(adminAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite project user failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var invitation map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&invitation)
	if invitation["email"] != "invitee@e2e.com" {
		t.Fatalf("invitation email mismatch: %v", invitation["email"])
	}

	// 3. List invitations
	req, _ = http.NewRequest(http.MethodGet, projectBaseURL+"/projects/"+projectID+"/invitations", nil)
	req.Header.Set(adminAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list project invitations failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var listResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&listResp)
	invs, ok := listResp["invitations"].([]interface{})
	if !ok || len(invs) == 0 {
		t.Fatal("no invitations returned")
	}

	// 4. Error: invite with missing email
	inviteReq = map[string]interface{}{
		"role": "member",
	}
	inviteBody, _ = json.Marshal(inviteReq)
	req, _ = http.NewRequest(http.MethodPost, projectBaseURL+"/projects/"+projectID+"/invitations", bytes.NewReader(inviteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(adminAuthHeader, "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invite project user (missing email) failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
