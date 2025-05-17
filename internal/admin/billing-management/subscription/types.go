package subscription

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)

// SubscriptionHandler is the handler for subscription-related routes
type SubscriptionHandler struct {
	PlanService         PlanService
	UsageService        UsageService
	SubscriptionService SubscriptionService
	Store               *PostgresStore
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

// SubscriptionPluginRegistry holds registered plugins by name.
type SubscriptionPluginRegistry struct {
	plugins map[string]SubscriptionPlugin
}

func (r *SubscriptionPluginRegistry) Register(name string, plugin SubscriptionPlugin) {
	if r.plugins == nil {
		r.plugins = make(map[string]SubscriptionPlugin)
	}
	r.plugins[name] = plugin
}

func (r *SubscriptionPluginRegistry) Lookup(name string) (SubscriptionPlugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

func (r *SubscriptionPluginRegistry) Unregister(name string) {
	if r.plugins == nil {
		return
	}
	delete(r.plugins, name)
}

func (r *SubscriptionPluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// SubscriptionPluginConfig stores per-tenant plugin selection.
type SubscriptionPluginConfig struct {
	TenantID   string    `json:"tenant_id"`
	PluginName string    `json:"plugin_name"`
	UpdatedAt  time.Time `json:"updated_at"`
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
	PluginName         string     `json:"plugin_name"`
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

// Global registry for subscription plugins
var SubscriptionPlugins = &SubscriptionPluginRegistry{plugins: make(map[string]SubscriptionPlugin)}

// RegisterSubscriptionPlugin registers a subscription plugin by name at runtime.
func RegisterSubscriptionPlugin(name string, plugin SubscriptionPlugin) {
	SubscriptionPlugins.Register(name, plugin)
}

// UnregisterSubscriptionPlugin removes a subscription plugin by name at runtime.
func UnregisterSubscriptionPlugin(name string) {
	SubscriptionPlugins.Unregister(name)
}

// ListSubscriptionPlugins returns all registered subscription plugin names.
func ListSubscriptionPlugins() []string {
	return SubscriptionPlugins.List()
}
