package security_management

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
)

// To avoid import cycles, define a minimal local interface for ServerConfigService
// Only the method(s) needed for JWT secret fetch are included

// JWTSecretConfig represents the owner-admin JWT secret config, stored as JSON in server_config
// This enables runtime, DB-backed, hot-reloadable JWT secret config for owner-admin
// Key: "owner_admin_jwt_secret_config"
type JWTSecretConfig struct {
	SecretName string `json:"secret_name"`
}

type ServerConfigService interface {
	GetOwnerJWTSecretConfig(ctx context.Context) (JWTSecretConfig, error)
}

type PostgresStore struct {
	DB                  *pgxpool.Pool

	ServerConfigService ServerConfigService
}

// Define a minimal UserService interface locally to avoid import cycle
// Only the method(s) needed for password reset notification are included

type UserService interface {
	GetUser(ctx context.Context, id string) (User, error)
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
	Store                       *PostgresStore
	SecurityAnalyticsService    SecurityAnalyticsService
	NotificationService         NotificationService
	SecurityModuleConfigService SecurityModuleConfigService
	UserService                 UserService
	ConfigurationService        ConfigurationService
	NotificationQueueService    NotificationQueueService
	OwnerJWTSecretConfigService OwnerJWTSecretConfigService
	Auth                        *auth.AuthManager
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
	Status    string    `json:"status"`
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

// Use the Session type from interfaces
type Session = interfaces.Session

// SecurityAuditLog represents a security-related audit log entry
type SecurityAuditLog struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	ActorID    string                 `json:"actor_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	TargetID   string                 `json:"target_id"`
	Details    string                 `json:"details"`
	IP         string                 `json:"ip"`
	UserAgent  string                 `json:"user_agent"`
	CreatedAt  time.Time              `json:"created_at"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
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

// Anomaly represents a security anomaly detected by the system
type Anomaly struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"` // high, medium, low
	Description string                 `json:"description"`
	Details     string                 `json:"details"`
	UserID      string                 `json:"user_id,omitempty"`
	DetectedAt  time.Time              `json:"detected_at"`
	CreatedAt   time.Time              `json:"created_at"`
	Status      string                 `json:"status"` // open, acknowledged, resolved
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
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

// NotificationConfig, RateLimitConfig, etc. already present, add Validate() methods
func (c NotificationConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if len(c.Channels) == 0 {
		return errors.New("at least one channel required")
	}
	if len(c.Recipients) == 0 {
		return errors.New("at least one recipient required")
	}
	return nil
}

func (c RateLimitConfig) Validate() error {
	if c.Scope == "" {
		return errors.New("scope required")
	}
	if c.ScopeID == "" {
		return errors.New("scope_id required")
	}
	if c.Limit <= 0 {
		return errors.New("limit must be > 0")
	}
	if c.WindowSeconds <= 0 {
		return errors.New("window_seconds must be > 0")
	}
	return nil
}

// NotificationChannelEnabledConfig holds enabled/disabled state for a notification channel/provider/tenant
// Key: notification_channel_enabled_{tenantID}_{channel}_{provider}
type NotificationChannelEnabledConfig struct {
	TenantID string `json:"tenant_id"`
	Channel  string `json:"channel"`
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
}

func (c NotificationChannelEnabledConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.Channel == "" {
		return errors.New("channel required")
	}
	if c.Provider == "" {
		return errors.New("provider required")
	}
	return nil
}

// OAuthConfigDB holds OAuth config for a tenant (DB-backed)
type OAuthConfigDB struct {
	TenantID     string   `json:"tenant_id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  string   `json:"redirect_uri"`
	Scopes       []string `json:"scopes"`
}

func (c OAuthConfigDB) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.ClientID == "" {
		return errors.New("client_id required")
	}
	if c.ClientSecret == "" {
		return errors.New("client_secret required")
	}
	if c.RedirectURI == "" {
		return errors.New("redirect_uri required")
	}
	return nil
}

// SAMLConfigDB holds SAML config for a tenant (DB-backed)
type SAMLConfigDB struct {
	TenantID    string `json:"tenant_id"`
	MetadataURL string `json:"metadata_url"`
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
}

func (c SAMLConfigDB) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.MetadataURL == "" {
		return errors.New("metadata_url required")
	}
	if c.EntityID == "" {
		return errors.New("entity_id required")
	}
	if c.ACSURL == "" {
		return errors.New("acs_url required")
	}
	return nil
}

// MFAConfig holds MFA settings for a tenant
type MFAConfig struct {
	TenantID          string   `json:"tenant_id"`
	Enabled           bool     `json:"enabled"`
	RequireMFA        bool     `json:"require_mfa"`
	AllowedMethods    []string `json:"allowed_methods"`
	MFATimeoutSeconds int      `json:"mfa_timeout_seconds"`
	Required          bool     `json:"required"`
	Providers         []string `json:"providers"`
}

func (c MFAConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if len(c.Providers) == 0 {
		return errors.New("at least one provider required")
	}
	return nil
}

// ProviderConfig holds provider settings for a tenant/channel
type ProviderConfig struct {
	TenantID string            `json:"tenant_id"`
	Channel  string            `json:"channel"`
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"`
}

func (c ProviderConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.Channel == "" {
		return errors.New("channel required")
	}
	if c.Provider == "" {
		return errors.New("provider required")
	}
	if len(c.Config) == 0 {
		return errors.New("config required")
	}
	return nil
}

// PasswordPolicyConfig holds password policy for a tenant
type PasswordPolicyConfig struct {
	TenantID       string `json:"tenant_id"`
	MinLength      int    `json:"min_length"`
	RequireNumbers bool   `json:"require_numbers"`
	RequireSpecial bool   `json:"require_special"`
	RequireUpper   bool   `json:"require_upper"`
	RequireLower   bool   `json:"require_lower"`
}

func (c PasswordPolicyConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.MinLength < 8 {
		return errors.New("min_length must be >= 8")
	}
	return nil
}

// SessionConfig holds session settings for a tenant
type SessionConfig struct {
	TenantID              string `json:"tenant_id"`
	SessionTimeoutMinutes int    `json:"session_timeout_minutes"`
	IdleTimeoutMinutes    int    `json:"idle_timeout_minutes"`
}

func (c SessionConfig) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if c.SessionTimeoutMinutes < 5 {
		return errors.New("session_timeout_minutes must be >= 5")
	}
	if c.IdleTimeoutMinutes < 1 {
		return errors.New("idle_timeout_minutes must be >= 1")
	}
	return nil
}

// NotificationQueueItem represents an item in the notification queue
// This struct must match the notification_queue table columns and usage in stores.go
// Details is a map for arbitrary notification data
// To is a slice of recipient addresses (email, phone, etc.)
type NotificationQueueItem struct {
	ID        string                 `json:"id"`
	Provider  string                 `json:"provider"`
	To        []string               `json:"to"`
	Event     string                 `json:"event"`
	Details   map[string]interface{} `json:"details"`
	Retry     int                    `json:"retry"`
	MaxRetry  int                    `json:"max_retry"`
	Status    string                 `json:"status"`
	LastError string                 `json:"last_error"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// AuthTypeConfigDB represents DB-backed config for authentication type (e.g., password, SSO, etc.)
// This is speculative, as no definition was found in the codebase. Adjust as needed.
type AuthTypeConfigDB struct {
	TenantID        string    `json:"tenant_id"`
	MFAEnabled      bool      `json:"mfa_enabled"`
	PasswordEnabled bool      `json:"password_enabled"`
	OAuthEnabled    bool      `json:"oauth_enabled"`
	SAMLEnabled     bool      `json:"saml_enabled"`
	AuthTypes       []string  `json:"auth_types"` // e.g., ["password", "saml", "oauth"]
	Primary         string    `json:"primary"`    // e.g., "password"
	Fallback        []string  `json:"fallback"`   // e.g., ["otp"]
	UpdatedAt       time.Time `json:"updated_at"`
}

func (c AuthTypeConfigDB) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id required")
	}
	if !c.MFAEnabled && !c.PasswordEnabled && !c.OAuthEnabled && !c.SAMLEnabled {
		return errors.New("at least one auth method must be enabled")
	}
	if c.Primary != "" {
		found := false
		for _, t := range c.AuthTypes {
			if t == c.Primary {
				found = true
				break
			}
		}
		if !found {
			return errors.New("primary auth type must be in auth_types")
		}
	}
	return nil
}

// UserMFAStatus represents a user's MFA configuration
type UserMFAStatus struct {
	UserID      string    `json:"user_id"`
	Enabled     bool      `json:"enabled"`
	Methods     []string  `json:"methods,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
}
