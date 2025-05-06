package domain

import "time"

// OptimizationGoal defines the type of optimization
const (
	OptimizationGoalCost        = "cost"
	OptimizationGoalPerformance = "performance"
	OptimizationGoalSecurity    = "security"
	OptimizationGoalMulti       = "multi"
)

// OptimizationSource defines the source of a recommendation
const (
	OptimizationSourceOpenAI = "openai"
	OptimizationSourceAWS    = "aws"
	OptimizationSourceAzure  = "azure"
	OptimizationSourceGCP    = "gcp"
)

// OptimizationStatus defines the status of a recommendation
const (
	OptimizationStatusNew       = "new"
	OptimizationStatusApplied   = "applied"
	OptimizationStatusIgnored   = "ignored"
	OptimizationStatusDismissed = "dismissed"
)

// OptimizationRequest is the input for generating recommendations
// Matches OpenAPI schema
type OptimizationRequest struct {
	TenantID   string   `json:"tenant_id"`
	ProjectID  string   `json:"project_id"`
	Scope      string   `json:"scope"`
	Resources  []string `json:"resources"`
	TimeWindow string   `json:"time_window"`
	Goal       string   `json:"goal"`
}

// OptimizationRecommendation is a single recommendation
// Matches OpenAPI schema
type OptimizationRecommendation struct {
	ID          string    `json:"id"`
	ResourceID  string    `json:"resource_id"`
	Type        string    `json:"type"`
	Impact      string    `json:"impact"`
	Rationale   string    `json:"rationale"`
	Remediation string    `json:"remediation"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PaymentMethod represents a PCI-compliant payment method for an account
// Only non-sensitive metadata is stored: last4, exp, provider, token, token_provider
// All sensitive card/bank data is tokenized and never stored in the DB
// Token is a reference to the vault/tokenization provider (e.g., Stripe, Adyen, AWS KMS)
type PaymentMethod struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"account_id"`
	Type          string    `json:"type"`
	Provider      string    `json:"provider"`
	Last4         string    `json:"last4"`
	ExpMonth      int       `json:"exp_month"`
	ExpYear       int       `json:"exp_year"`
	IsDefault     bool      `json:"is_default"`
	Status        string    `json:"status"`
	Token         string    `json:"token"`          // PCI token reference, never raw PAN
	TokenProvider string    `json:"token_provider"` // e.g., stripe, adyen, aws_kms
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Metadata      string    `json:"metadata"`
}
