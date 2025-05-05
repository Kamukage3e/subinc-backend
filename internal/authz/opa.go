package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/viper"
)

// OPAClient is a production-ready client for querying OPA REST API.
type OPAClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewOPAClient creates a new OPA client with config from Viper/env.
func NewOPAClient() *OPAClient {
	baseURL := viper.GetString("OPA_URL")
	if baseURL == "" {
		baseURL = os.Getenv("OPA_URL")
	}
	if baseURL == "" {
		baseURL = "http://localhost:8181" // secure default for local dev only
	}
	return &OPAClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// OPAInput is the input sent to OPA for policy evaluation.
type OPAInput struct {
	User     string      `json:"user"`
	Roles    []string    `json:"roles"`
	Tenant   string      `json:"tenant"`
	Action   string      `json:"action"`
	Resource string      `json:"resource"`
	Context  interface{} `json:"context,omitempty"`
}

// OPAResult is the expected output from OPA.
type OPAResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

type opaResponse struct {
	Result OPAResult `json:"result"`
}

// Query queries OPA for an authorization decision.
func (c *OPAClient) Query(ctx context.Context, policyPath string, input OPAInput) (OPAResult, error) {
	var result OPAResult
	url := fmt.Sprintf("%s/v1/data/%s", c.baseURL, policyPath)
	body, err := json.Marshal(map[string]interface{}{"input": input})
	if err != nil {
		return result, fmt.Errorf("failed to marshal OPA input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(b))
	}
	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return result, fmt.Errorf("failed to decode OPA response: %w", err)
	}
	return opaResp.Result, nil
}
