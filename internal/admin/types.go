package admin

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/email"
	"github.com/subinc/subinc-backend/internal/user"

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
	ProjectID  string    `json:"project_id,omitempty" db:"project_id"`
	OrgID      string    `json:"org_id,omitempty" db:"org_id"`
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
	store interface {
		AdminStore
		AdminUserStore
	}
	userStore      *user.PostgresUserStore // For all user/org/project role/permission logic
	emailManager   *email.EmailManager
	SecretsManager interface{}
	JWTSecretName  string
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

// Built-in admin roles for RBAC
const (
	RoleSupport   = "support"
	RoleMarketing = "marketing"
	RoleSSM       = "ssm"
)

// Built-in admin permissions for RBAC
const (
	PermSupportViewTickets   = "support:view_tickets"
	PermSupportManageUsers   = "support:manage_users"
	PermMarketingViewReports = "marketing:view_reports"
	PermMarketingSendEmails  = "marketing:send_emails"
	PermSSMManageBlogs       = "ssm:manage_blogs"
	PermSSMManageNews        = "ssm:manage_news"
)

type Project struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	OwnerID     string    `json:"owner_id" db:"owner_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type ProjectFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

type Organization struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type OrganizationFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

// OrgTeam represents a team within an organization for admin endpoints
// All fields are required for production SaaS
// Team membership is managed via user IDs for RBAC
// Team settings is a JSON blob for extensibility
// CreatedAt/UpdatedAt are UTC
type OrgTeam struct {
	ID          string    `json:"id" db:"id"`
	OrgID       string    `json:"org_id" db:"org_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	UserIDs     []string  `json:"user_ids" db:"user_ids"`
	Settings    string    `json:"settings" db:"settings"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type OrgTeamFilter struct {
	OrgID   string
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

// SSMBlog represents a blog post for SSM team
// Used for /admin/ssm/blogs endpoints
// All fields are required for production SaaS
type SSMBlog struct {
	ID        string    `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Body      string    `json:"body" db:"body"`
	AuthorID  string    `json:"author_id" db:"author_id"`
	Tags      []string  `json:"tags" db:"tags"`
	Status    string    `json:"status" db:"status"` // draft, published, archived
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type SSMBlogFilter struct {
	Query   string
	Status  string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

// SSMNews represents a news item for SSM team
// Used for /admin/ssm/news endpoints
// All fields are required for production SaaS
type SSMNews struct {
	ID        string    `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Body      string    `json:"body" db:"body"`
	AuthorID  string    `json:"author_id" db:"author_id"`
	Status    string    `json:"status" db:"status"` // draft, published, archived
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type SSMNewsFilter struct {
	Query   string
	Status  string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}

// ProjectInvitation represents an invitation to a project
// Used for admin/project invitation flows
// All fields required for production SaaS
// CreatedAt/UpdatedAt are UTC
type ProjectInvitation struct {
	ID        string    `json:"id" db:"id"`
	ProjectID string    `json:"project_id" db:"project_id"`
	Email     string    `json:"email" db:"email"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// OrgInvitation represents an invitation to an organization
// Used for admin/org invitation flows
// All fields required for production SaaS
// CreatedAt/UpdatedAt are UTC
type OrgInvitation struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	Email     string    `json:"email" db:"email"`
	Role      string    `json:"role" db:"role"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
