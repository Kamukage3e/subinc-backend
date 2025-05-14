package subscription

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)


type SubscriptionHandler struct {
	PlanService                PlanService
	UsageService               UsageService
	SubscriptionService        SubscriptionService
	RBACService         rbac_management.RBACService
	ServerConfigService server_config.Service
	Store               PostgresStore
}


type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

type Plan struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       float64   `json:"price"`
	Currency    string    `json:"currency"` // ISO 4217, e.g. USD
	Active      bool      `json:"active"`
	Pricing     string    `json:"pricing"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (p *Plan) Validate() *Error {
	if p.Name == "" {
		return NewValidationError("name", "must not be empty")
	}
	if p.Price < 0 {
		return NewValidationError("price", "must be non-negative")
	}
	return nil
}

type Usage struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Metric    string    `json:"metric"`
	Amount    float64   `json:"amount"`
	Period    string    `json:"period"`
	CreatedAt time.Time `json:"created_at"`
}

func (u *Usage) Validate() *Error {
	if u.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if u.Metric == "" {
		return NewValidationError("metric", "must not be empty")
	}
	if u.Amount < 0 {
		return NewValidationError("amount", "must be non-negative")
	}
	return nil
}


type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}


type Subscription struct {
	ID                 string     `json:"id"`
	AccountID          string     `json:"account_id"`
	PlanID             string     `json:"plan_id"`
	Status             string     `json:"status"`
	Currency           string     `json:"currency"` // ISO 4217, e.g. USD
	TrialStart         *time.Time `json:"trial_start,omitempty"`
	TrialEnd           *time.Time `json:"trial_end,omitempty"`
	CurrentPeriodStart time.Time  `json:"current_period_start"`
	CurrentPeriodEnd   time.Time  `json:"current_period_end"`
	CancelAt           *time.Time `json:"cancel_at,omitempty"`
	CanceledAt         *time.Time `json:"canceled_at,omitempty"`
	GracePeriodEnd     *time.Time `json:"grace_period_end,omitempty"`
	DunningUntil       *time.Time `json:"dunning_until,omitempty"`
	ScheduledPlanID    *string    `json:"scheduled_plan_id,omitempty"`
	ScheduledChangeAt  *time.Time `json:"scheduled_change_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	Metadata           string     `json:"metadata"`
}

func (s *Subscription) Validate() *Error {
	if s.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if s.PlanID == "" {
		return NewValidationError("plan_id", "must not be empty")
	}
	if s.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}