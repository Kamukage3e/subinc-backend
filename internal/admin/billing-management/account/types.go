package account

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)

// AccountHandler handles dynamic account endpoints for user, project, and organization billing accounts.
type AccountHandler struct {
	BillingAccountService BillingAccountService
	NotificationService   security_management.NotificationService
	RateLimitService      *security_management.RateLimitService
}

type UserBillingAccount struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	Currency  string    `json:"currency"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProjectBillingAccount struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	Currency  string    `json:"currency"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OrganizationBillingAccount struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	Currency  string    `json:"currency"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PostgresStore struct {
	DB                  *pgxpool.Pool
	AuditLogger         security_management.AuditLogger
	ServerConfigService *server_config.Service
}

type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func (a *ProjectBillingAccount) Validate() *Error {
	if a.ProjectID == "" {
		return NewValidationError("project_id", "must not be empty")
	}
	if a.TenantID == "" {
		return NewValidationError("tenant_id", "must not be empty")
	}
	if a.Email == "" {
		return NewValidationError("email", "must not be empty")
	}
	if a.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

func (a *UserBillingAccount) Validate() *Error {
	if a.UserID == "" {
		return NewValidationError("user_id", "must not be empty")
	}
	if a.TenantID == "" {
		return NewValidationError("tenant_id", "must not be empty")
	}
	if a.Email == "" {
		return NewValidationError("email", "must not be empty")
	}
	if a.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

func (a *OrganizationBillingAccount) Validate() *Error {
	if a.OrgID == "" {
		return NewValidationError("org_id", "must not be empty")
	}
	if a.TenantID == "" {
		return NewValidationError("tenant_id", "must not be empty")
	}
	if a.Email == "" {
		return NewValidationError("email", "must not be empty")
	}
	if a.Status == "" {
		return NewValidationError("status", "must not be empty")
	}
	return nil
}

func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
