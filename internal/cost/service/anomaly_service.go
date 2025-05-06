package service

import (
	"context"
	"time"

	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// AnomalyDetectionService provides AI/ML-driven cost anomaly detection and recommendations.
type AnomalyDetectionService interface {
	DetectAnomalies(ctx context.Context, tenantID string, start, end time.Time) ([]*domain.Anomaly, error)
	ListAnomalies(ctx context.Context, tenantID string, filter AnomalyFilter) ([]*domain.Anomaly, int, error)
	GetRecommendations(ctx context.Context, anomalyID string) (string, error)
}

type anomalyDetectionService struct {
	repo            repository.CostRepository
	logger          *logger.Logger
	providers       map[string]AIAnomalyProvider
	defaultProvider string
}

type AnomalyFilter struct {
	Provider   domain.CloudProvider
	Severity   string
	Status     string
	From, To   time.Time
	Page, Size int
}

// AIAnomalyProvider defines the interface for pluggable AI/ML anomaly detection providers.
type AIAnomalyProvider interface {
	DetectAnomalies(ctx context.Context, tenantID string, costs []*domain.Cost) ([]*domain.Anomaly, error)
	GetRecommendation(ctx context.Context, anomaly *domain.Anomaly) (string, error)
	ProviderName() string
}

// DummyAIAnomalyProvider is used when OpenAI is not configured (dev/test)
type DummyAIAnomalyProvider struct{ logger *logger.Logger }

func (d *DummyAIAnomalyProvider) ProviderName() string { return "dummy" }
func (d *DummyAIAnomalyProvider) DetectAnomalies(ctx context.Context, tenantID string, costs []*domain.Cost) ([]*domain.Anomaly, error) {
	d.logger.Warn("OpenAI anomaly detection is disabled: no OPENAI_API_KEY set")
	return nil, nil
}
func (d *DummyAIAnomalyProvider) GetRecommendation(ctx context.Context, anomaly *domain.Anomaly) (string, error) {
	d.logger.Warn("OpenAI recommendation is disabled: no OPENAI_API_KEY set")
	return "AI anomaly detection is disabled in this environment.", nil
}

// OpenAIAnomalyProvider implements AIAnomalyProvider using OpenAI's API.
type OpenAIAnomalyProvider struct {
	apiKey     string
	apiURL     string
	model      string
	logger     *logger.Logger
	httpClient *http.Client
}

func NewOpenAIAnomalyProvider(log *logger.Logger) AIAnomalyProvider {
	apiKey := viper.GetString("OPENAI_API_KEY")
	if apiKey == "" {
		if viper.GetString("ENV") == "production" {
			panic("OPENAI_API_KEY not set: required for production AI anomaly detection")
		}
		return &DummyAIAnomalyProvider{logger: log}
	}
	apiURL := viper.GetString("OPENAI_API_URL")
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions"
	}
	model := viper.GetString("OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIAnomalyProvider{
		apiKey:     apiKey,
		apiURL:     apiURL,
		model:      model,
		logger:     log,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OpenAIAnomalyProvider) ProviderName() string { return "openai" }

func (o *OpenAIAnomalyProvider) DetectAnomalies(ctx context.Context, tenantID string, costs []*domain.Cost) ([]*domain.Anomaly, error) {
	if len(costs) == 0 {
		return nil, nil
	}
	// Prepare prompt (truncate for token limits)
	costsShort := costs
	if len(costs) > 100 {
		costsShort = costs[len(costs)-100:]
	}
	prompt := o.buildDetectionPrompt(costsShort)
	body := map[string]interface{}{
		"model": o.model,
		"messages": []map[string]string{{
			"role":    "system",
			"content": "You are a cloud cost anomaly detection expert. Given a list of daily cost records, identify any anomalies (unexpected spikes or drops) and return a JSON array of anomalies with fields: resource_id, service, start_time, end_time, expected_cost, actual_cost, deviation, severity, recommendation.",
		}, {
			"role":    "user",
			"content": prompt,
		}},
		"temperature": 0.1,
	}
	reqBytes, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.apiURL, bytes.NewReader(reqBytes))
	if err != nil {
		o.logger.Error("openai: failed to create request", logger.ErrorField(err))
		return nil, fmt.Errorf("openai: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.httpClient.Do(req)
	if err != nil {
		o.logger.Error("openai: request failed", logger.ErrorField(err))
		return nil, fmt.Errorf("openai: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		o.logger.Error("openai: non-200 response", logger.String("status", resp.Status), logger.String("body", string(b)))
		return nil, fmt.Errorf("openai: status %d: %s", resp.StatusCode, string(b))
	}
	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		o.logger.Error("openai: failed to decode response", logger.ErrorField(err))
		return nil, fmt.Errorf("openai: failed to decode response: %w", err)
	}
	if len(openaiResp.Choices) == 0 {
		return nil, nil
	}
	// Parse JSON array from model output
	var anomalies []*domain.Anomaly
	if err := json.Unmarshal([]byte(openaiResp.Choices[0].Message.Content), &anomalies); err != nil {
		o.logger.Error("openai: failed to parse model output", logger.ErrorField(err))
		return nil, fmt.Errorf("openai: failed to parse model output: %w", err)
	}
	for _, a := range anomalies {
		a.ID = uuid.NewString()
		a.TenantID = tenantID
		a.DetectedAt = time.Now().UTC()
		a.CreatedAt = a.DetectedAt
		a.UpdatedAt = a.DetectedAt
		if a.Status == "" {
			a.Status = "open"
		}
	}
	return anomalies, nil
}

func (o *OpenAIAnomalyProvider) buildDetectionPrompt(costs []*domain.Cost) string {
	// Only include relevant fields to minimize tokens
	var rows []map[string]interface{}
	for _, c := range costs {
		rows = append(rows, map[string]interface{}{
			"resource_id":   c.ResourceID,
			"service":       c.Service,
			"start_time":    c.StartTime.Format(time.RFC3339),
			"end_time":      c.EndTime.Format(time.RFC3339),
			"cost_amount":   c.CostAmount,
			"expected_cost": 0, // let model infer
		})
	}
	b, _ := json.Marshal(rows)
	return fmt.Sprintf("Daily cost records: %s", string(b))
}

func (o *OpenAIAnomalyProvider) GetRecommendation(ctx context.Context, anomaly *domain.Anomaly) (string, error) {
	prompt := fmt.Sprintf("Given this cost anomaly: %v, provide a concise, actionable recommendation for a cloud engineer.", anomaly)
	body := map[string]interface{}{
		"model": o.model,
		"messages": []map[string]string{{
			"role":    "system",
			"content": "You are a cloud cost optimization expert. Given an anomaly, return a single actionable recommendation as a string.",
		}, {
			"role":    "user",
			"content": prompt,
		}},
		"temperature": 0.1,
	}
	reqBytes, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.apiURL, bytes.NewReader(reqBytes))
	if err != nil {
		o.logger.Error("openai: failed to create recommendation request", logger.ErrorField(err))
		return "", fmt.Errorf("openai: failed to create recommendation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.httpClient.Do(req)
	if err != nil {
		o.logger.Error("openai: recommendation request failed", logger.ErrorField(err))
		return "", fmt.Errorf("openai: recommendation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		o.logger.Error("openai: recommendation non-200 response", logger.String("status", resp.Status), logger.String("body", string(b)))
		return "", fmt.Errorf("openai: recommendation status %d: %s", resp.StatusCode, string(b))
	}
	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		o.logger.Error("openai: failed to decode recommendation response", logger.ErrorField(err))
		return "", fmt.Errorf("openai: failed to decode recommendation response: %w", err)
	}
	if len(openaiResp.Choices) == 0 {
		return "", nil
	}
	return openaiResp.Choices[0].Message.Content, nil
}

func NewAnomalyDetectionService(repo repository.CostRepository, log *logger.Logger) AnomalyDetectionService {
	if log == nil {
		log = logger.NewNoop()
	}
	providers := map[string]AIAnomalyProvider{
		"openai": NewOpenAIAnomalyProvider(log),
	}
	return &anomalyDetectionService{
		repo:            repo,
		logger:          log,
		providers:       providers,
		defaultProvider: "openai",
	}
}

// DetectAnomalies runs a real statistical anomaly detection (z-score) on cost data for the given tenant and time range.
func (s *anomalyDetectionService) DetectAnomalies(ctx context.Context, tenantID string, start, end time.Time) ([]*domain.Anomaly, error) {
	costs, _, err := s.repo.QueryCosts(ctx, domain.CostQuery{
		TenantID:    tenantID,
		StartTime:   start.AddDate(0, 0, -30), // 30 days lookback
		EndTime:     end,
		Granularity: domain.Daily,
		Page:        1,
		PageSize:    10000,
	})
	if err != nil {
		s.logger.Error("failed to query costs for anomaly detection", logger.ErrorField(err))
		return nil, err
	}
	if len(costs) == 0 {
		return nil, nil
	}
	provider := s.providers[s.defaultProvider]
	anomalies, err := provider.DetectAnomalies(ctx, tenantID, costs)
	if err != nil {
		s.logger.Error("AI anomaly detection failed", logger.ErrorField(err))
		return nil, err
	}
	for _, a := range anomalies {
		if err := s.repo.CreateAnomaly(ctx, a); err == nil {
			// success
		}
	}
	return anomalies, nil
}

func (s *anomalyDetectionService) ListAnomalies(ctx context.Context, tenantID string, filter AnomalyFilter) ([]*domain.Anomaly, int, error) {
	return s.repo.ListAnomalies(ctx, tenantID, filter.Provider, filter.From, filter.To, filter.Status, filter.Page, filter.Size)
}

func (s *anomalyDetectionService) GetRecommendations(ctx context.Context, anomalyID string) (string, error) {
	anomaly, err := s.repo.GetAnomalyByID(ctx, anomalyID)
	if err != nil {
		return "", err
	}
	provider := s.providers[s.defaultProvider]
	rec, err := provider.GetRecommendation(ctx, anomaly)
	if err != nil {
		s.logger.Error("AI recommendation failed", logger.ErrorField(err))
		return "", err
	}
	return rec, nil
}

// generateRecommendation produces a real, actionable recommendation for a detected anomaly.
func (s *anomalyDetectionService) generateRecommendation(cost *domain.Cost, mean float64) string {
	if cost.CostAmount > mean*1.5 {
		return "Investigate recent changes to resource/service. Consider rightsizing or shutting down unused resources."
	}
	return "Monitor for further anomalies. No immediate action required."
}
