package account

import (

	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
)

// AccountHandler handles account endpoints
type AccountHandler struct {
	AccountService      AccountService
	NotificationService security_management.NotificationService
}

type Account struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Status    string    `json:"status"`
	Currency  string    `json:"currency"` // ISO 4217, e.g. USD
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

func (a *Account) Validate() *Error {
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



// AccountPluginRegistry manages account plugins
// All methods concurrency-safe
type AccountPluginRegistry struct {
	plugins map[string]AccountPlugin
}

// Register adds an account plugin to the registry
func (r *AccountPluginRegistry) Register(plugin AccountPlugin) {
	if plugin == nil {
		return
	}
	name := plugin.Name()
	if name == "" {
		return
	}
	if r.plugins == nil {
		r.plugins = make(map[string]AccountPlugin)
	}
	r.plugins[name] = plugin
}

// Unregister removes an account plugin from the registry
func (r *AccountPluginRegistry) Unregister(name string) {
	if r.plugins == nil {
		return
	}
	delete(r.plugins, name)
}

// Lookup retrieves an account plugin by name
func (r *AccountPluginRegistry) Lookup(name string) (AccountPlugin, bool) {
	if r.plugins == nil {
		return nil, false
	}
	p, ok := r.plugins[name]
	return p, ok
}

// List returns all registered account plugin names
func (r *AccountPluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Global registry for account plugins
var AccountPlugins = &AccountPluginRegistry{plugins: make(map[string]AccountPlugin)}
