package admin

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/pkg/session"
)

// AuditLogFilter defines filter/search params for audit log queries
// Shared between handler and store for DRY
// All fields are optional; zero values mean no filter
// Used for admin audit log search/filter/export
// This struct is production-grade and ready for SaaS
type AuditLogFilter struct {
	ActorID  string
	Action   string
	Resource string
	Start    *time.Time
	End      *time.Time
	Limit    int
	Offset   int
}

// User/tenant/role/permission filter structs for DRY search/filter/sort/pagination
// Used by handler and store

type UserFilter struct {
	Query   string
	Role    string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

type TenantFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

type RoleFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

type PermissionFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

// APIKey represents an admin API key
// Only returned on create/rotate does key get populated
// Status is 'active' or 'revoked'
type APIKey struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	Name       string    `json:"name" db:"name"`
	Key        string    `json:"key,omitempty" db:"key"`
	Status     string    `json:"status" db:"status"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// APIKeyAuditLog represents an audit log entry for API key usage
type APIKeyAuditLog struct {
	ID        string    `json:"id" db:"id"`
	APIKeyID  string    `json:"api_key_id" db:"api_key_id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Action    string    `json:"action" db:"action"`
	Details   string    `json:"details" db:"details"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Notification represents an admin notification (system, security, billing, etc)
type Notification struct {
	ID        string     `json:"id" db:"id"`
	Type      string     `json:"type" db:"type"`
	Recipient string     `json:"recipient" db:"recipient"`
	Subject   string     `json:"subject" db:"subject"`
	Body      string     `json:"body" db:"body"`
	Status    string     `json:"status" db:"status"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	SentAt    *time.Time `json:"sent_at,omitempty" db:"sent_at"`
}

// RateLimitConfig represents admin rate limit config and status
type RateLimitConfig struct {
	Global   *RateLimitRule   `json:"global"`
	PerRoute []RateLimitRule  `json:"per_route"`
	Status   *RateLimitStatus `json:"status"`
}

type RateLimitRule struct {
	Route         string `json:"route,omitempty"`
	MaxRequests   int    `json:"max_requests"`
	WindowSeconds int    `json:"window_seconds"`
}

type RateLimitStatus struct {
	CurrentUsage int       `json:"current_usage"`
	ResetAt      time.Time `json:"reset_at"`
}

type RateLimitConfigInput struct {
	Global   *RateLimitRule  `json:"global"`
	PerRoute []RateLimitRule `json:"per_route"`
}

// MaintenanceModeStatus represents maintenance mode status for admin
// Used for /admin/system/maintenance endpoints
type MaintenanceModeStatus struct {
	Maintenance bool      `json:"maintenance"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type MaintenanceModeInput struct {
	Maintenance bool `json:"maintenance"`
}

// MonitoringConfig represents real-time monitoring config and status for admin
// Used for /admin/monitoring endpoints
type MonitoringConfig struct {
	Enabled   bool              `json:"enabled"`
	Providers []string          `json:"providers"`
	Status    *MonitoringStatus `json:"status"`
}

type MonitoringStatus struct {
	LastEventAt time.Time `json:"last_event_at"`
	EventCount  int       `json:"event_count"`
}

type MonitoringConfigInput struct {
	Enabled   bool     `json:"enabled"`
	Providers []string `json:"providers"`
}

// SecretsStatus represents secrets status for admin
// Used for /admin/secrets endpoints
type SecretsStatus struct {
	Secrets []SecretInfo `json:"secrets"`
}

type SecretInfo struct {
	KeyID       string    `json:"key_id"`
	Status      string    `json:"status"`
	LastRotated time.Time `json:"last_rotated"`
}

type SecretsUpdateInput struct {
	Rotate    bool   `json:"rotate"`
	KeyID     string `json:"key_id,omitempty"`
	NewSecret string `json:"new_secret,omitempty"`
}

// FeatureFlag represents a feature flag for admin
// Used for /admin/system/flags endpoints
type FeatureFlag struct {
	Flag      string    `json:"flag"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

type FeatureFlagInput struct {
	Flag    string `json:"flag"`
	Enabled bool   `json:"enabled"`
}

type AdminHandler struct {
	store AdminStore
}

// Policy defines the structure of a policy.
type Policy struct {
	ID        string                 `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	Type      string                 `json:"type" db:"type"`
	TargetID  string                 `json:"target_id" db:"target_id"`
	Rules     map[string]interface{} `json:"rules" db:"rules"`
	CreatedAt string                 `json:"created_at" db:"created_at"`
	UpdatedAt string                 `json:"updated_at" db:"updated_at"`
}

// PostgresAdminStore implements AdminStore using PostgreSQL.
type PostgresAdminStore struct {
	DB         *pgxpool.Pool
	SessionMgr *session.SessionManager
}

// AdminUser represents a privileged admin user (superuser, org admin, etc.)
type AdminUser struct {
	ID           string    `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Roles        []string  `json:"roles" db:"roles"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// AdminRole represents an admin role (e.g., superuser, compliance, billing)
type AdminRole struct {
	ID          string   `json:"id" db:"id"`
	Name        string   `json:"name" db:"name"`
	Permissions []string `json:"permissions" db:"permissions"`
}

// AdminPermission represents a named admin permission
type AdminPermission struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
}

// Tenant represents a real SaaS tenant/org. All fields are required for prod.
type Tenant struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"` // JSON blob for org settings/policies
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}