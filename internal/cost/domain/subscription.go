package domain

import (
	"time"
)

// Subscription represents a subscription for an account/plan
// All fields are required for SaaS billing and auditability
// Status: active, trialing, canceled, grace, dunning, past_due, scheduled, expired
// Metadata: JSON-encoded for extensibility

type Subscription struct {
	ID                 string     `json:"id"`
	AccountID          string     `json:"account_id"`
	PlanID             string     `json:"plan_id"`
	Status             string     `json:"status"`
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

func (s *Subscription) Validate() error {
	if s.AccountID == "" {
		return NewValidationError("account_id", "must not be empty")
	}
	if s.PlanID == "" {
		return NewValidationError("plan_id", "must not be empty")
	}
	if s.Status != "active" && s.Status != "trialing" && s.Status != "canceled" && s.Status != "grace" && s.Status != "dunning" && s.Status != "past_due" && s.Status != "scheduled" && s.Status != "expired" {
		return NewValidationError("status", "must be a valid subscription status")
	}
	if s.CurrentPeriodStart.IsZero() || s.CurrentPeriodEnd.IsZero() {
		return NewValidationError("current_period", "must not be zero")
	}
	return nil
}
