package security_management

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	DB          *pgxpool.Pool
	AuditLogger AuditLogger
}

// Define RBACService interface locally to avoid import cycle
// This must match the interface in handlers.go and rbac-management

type RBACService interface {
	CheckPermission(ctx interface{}, actorID, resource, action string) (bool, error)
}

type SecurityHandler struct {
	SecurityEventService        SecurityEventService
	SecurityEventWebhookService SecurityEventWebhookService
	LoginHistoryService         LoginHistoryService
	MFAService                  MFAService
	PasswordService             PasswordService
	PasswordResetTokenService   PasswordResetTokenService
	SessionService              SessionService
	SecurityAuditLogService     SecurityAuditLogService
	RateLimitService            RateLimitService
	APIKeyService               APIKeyService
	DeviceService               DeviceService
	BreachService               BreachService
	SecurityPolicyService       SecurityPolicyService
	RBACService                 RBACService
	Store                       *PostgresStore
	SecurityAnalyticsService    SecurityAnalyticsService
	NotificationService         NotificationService
	SecurityModuleConfigService SecurityModuleConfigService
	OwnerOAuthConfig            OAuthConfig
	OwnerSAMLConfig             SAMLConfig
	AuthTypeConfig              AuthTypeConfig
}

type SecurityEvent struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	EventType string    `json:"event_type"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type LoginHistory struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IP        string    `json:"ip"`
	Device    string    `json:"device"`
	Location  string    `json:"location"`
	Success   bool      `json:"success"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IP        string    `json:"ip"`
	Device    string    `json:"device"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SecurityAuditLog struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

type APIKey struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`
	Key       string     `json:"key"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Device struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Type      string     `json:"type"`
	Name      string     `json:"name"`
	IP        string     `json:"ip"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Breach struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Details    string    `json:"details"`
	DetectedAt time.Time `json:"detected_at"`
}

type SecurityPolicy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Rules     string    `json:"rules"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DBError struct {
	Op  string
	Err error
}

type SecurityAnalytics struct {
	TenantID    string    `json:"tenant_id"`
	RiskScore   float64   `json:"risk_score"`
	Posture     string    `json:"posture"`
	Anomalies   []Anomaly `json:"anomalies"`
	GeneratedAt time.Time `json:"generated_at"`
}

type Anomaly struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Details    string    `json:"details"`
	DetectedAt time.Time `json:"detected_at"`
}

type NotificationChannel string

const (
	NotificationEmail NotificationChannel = "email"
	NotificationSMS   NotificationChannel = "sms"
	NotificationSlack NotificationChannel = "slack"
)

type NotificationConfig struct {
	TenantID   string                `json:"tenant_id"`
	Channels   []NotificationChannel `json:"channels"`
	Recipients []string              `json:"recipients"`
	Events     []string              `json:"events"`
	Enabled    bool                  `json:"enabled"`
}

type SecurityModuleConfig struct {
	Enabled bool `json:"enabled"`
}

// SecurityEventWebhook represents a webhook subscription for security events
// All fields required for multi-tenant, secure event streaming
// EventTypes: list of event types to subscribe to (e.g., login, permission_change)
type SecurityEventWebhook struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"event_types"`
	Secret     string    `json:"secret"`
	Status     string    `json:"status"` // active, disabled
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PasswordResetToken represents a token for password reset/verification
// Used for token-based flows (not just admin reset)
type PasswordResetToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RateLimitConfig represents a rate limit for a tenant/org/user
// Scope: "tenant", "org", or "user"
type RateLimitConfig struct {
	ID            string    `json:"id"`
	Scope         string    `json:"scope"`
	ScopeID       string    `json:"scope_id"`
	Limit         int       `json:"limit"`
	WindowSeconds int       `json:"window_seconds"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type OAuthConfig struct {
	Google struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURI  string   `json:"redirect_uri"`
		Scopes       []string `json:"scopes"`
	} `json:"google"`
}

type SAMLConfig struct {
	MetadataURL string `json:"metadata_url"`
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
}

// AuthTypeConfig controls which auth types are enabled/optional/disabled at runtime.
type AuthTypeConfig struct {
	PasswordEnabled  bool
	PasswordOptional bool
	MFAEnabled       bool
	MFAOptional      bool
	OAuthEnabled     bool
	OAuthOptional    bool
	SAMLEnabled      bool
	SAMLOptional     bool
}

type NotificationQueueItem struct {
	ID        string                 `json:"id"`
	Provider  string                 `json:"provider"`
	To        []string               `json:"to"`
	Event     string                 `json:"event"`
	Details   map[string]interface{} `json:"details"`
	Retry     int                    `json:"retry"`
	MaxRetry  int                    `json:"max_retry"`
	Status    string                 `json:"status"` // pending, sent, failed, dead
	LastError string                 `json:"last_error"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}
