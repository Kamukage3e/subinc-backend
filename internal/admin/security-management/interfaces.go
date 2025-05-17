package security_management

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/interfaces"
)

type SecurityEventService interface {
	ListUserSecurityEvents(ctx context.Context, userID string) ([]SecurityEvent, error)
}

type LoginHistoryService interface {
	ListUserLoginHistory(ctx context.Context, userID string) ([]LoginHistory, error)
}

type MFAService interface {
	EnableMFA(ctx context.Context, userID string) error
	DisableMFA(ctx context.Context, userID string) error
	GenerateChallenge(ctx context.Context, userID string) (map[string]interface{}, error)
	VerifyChallenge(ctx context.Context, userID, code string) error
	GetUserMFAStatus(ctx context.Context, userID string) (UserMFAStatus, error)
}

type PasswordService interface {
	ResetUserPassword(ctx context.Context, userID, newPassword string) error
	AuthenticateUser(ctx context.Context, email, password string) (User, error)
	RegisterUser(ctx context.Context, email, password string) (User, error)
	VerifyEmail(ctx context.Context, userID, token string) error
	ResendVerification(ctx context.Context, email string) error
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	GetProfile(ctx context.Context, userID string) (map[string]interface{}, error)
	UpdateProfile(ctx context.Context, userID string, input map[string]interface{}) (map[string]interface{}, error)
	DeleteAccount(ctx context.Context, userID string) error
	Consent(ctx context.Context, userID, consent string) error
	SendInvite(ctx context.Context, email, role string) error
	AcceptInvite(ctx context.Context, token, email, password string) (User, error)
	AccountRecover(ctx context.Context, email string) error
	CountUsers(ctx context.Context) (int, error)
}

// SessionService defines the interface for session operations used in security management
// This interface combines both the new and legacy session operations to support
// the transition to the new unified session management
type SessionService interface {
	// Core session operations (new interface)
	CreateSession(ctx context.Context, userID, tenantID string, data map[string]interface{}) (interfaces.Session, error)
	GetSession(ctx context.Context, sessionID string) (interfaces.Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	RefreshSession(ctx context.Context, sessionID string) (interfaces.Session, error)

	// User session operations
	ListUserSessions(ctx context.Context, userID string) ([]interfaces.Session, error)

	// Legacy support methods for backward compatibility
	CreateUserSession(ctx context.Context, userID, ip, device string, expiresIn time.Duration) (interfaces.Session, error)
	RefreshUserSession(ctx context.Context, sessionID string, expiresIn time.Duration) (interfaces.Session, error)
	LogoutSession(ctx context.Context, sessionID string) error
	RevokeUserSession(ctx context.Context, userID, sessionID string) error
}

type SecurityAuditLogService interface {
	ListSecurityAuditLogs(ctx context.Context, page, pageSize int) ([]SecurityAuditLog, error)
	CreateSecurityAuditLog(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error)
}

type APIKeyService interface {
	ListUserAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	CreateUserAPIKey(ctx context.Context, userID, name string) (APIKey, error)
	RevokeUserAPIKey(ctx context.Context, userID, keyID string) error
}

type DeviceService interface {
	ListUserDevices(ctx context.Context, userID string) ([]Device, error)
	RevokeUserDevice(ctx context.Context, userID, deviceID string) error
	TrustDevice(ctx context.Context, userID, deviceID string) error
}

type BreachService interface {
	ListBreaches(ctx context.Context, page, pageSize int) ([]Breach, error)
}

type SecurityPolicyService interface {
	ListSecurityPolicies(ctx context.Context) ([]SecurityPolicy, error)
	CreateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error)
	UpdateSecurityPolicy(ctx context.Context, policy SecurityPolicy) (SecurityPolicy, error)
	DeleteSecurityPolicy(ctx context.Context, id string) error
}

// AuditLogger is the canonical interface for audit logging. All modules must depend on this, not a concrete implementation.
type AuditLogger interface {
	CreateSecurityAuditLog(ctx context.Context, log SecurityAuditLog) (SecurityAuditLog, error)
}

type SecurityAnalyticsService interface {
	GetSecurityAnalytics(ctx context.Context, tenantID string) (SecurityAnalytics, error)
	ListAnomalies(ctx context.Context, tenantID string, page, pageSize int) ([]Anomaly, error)
	DetectAnomalies(ctx context.Context, tenantID string) ([]Anomaly, error)
}

type NotificationService interface {
	GetNotificationConfig(ctx context.Context, tenantID string) (NotificationConfig, error)
	UpdateNotificationConfig(ctx context.Context, tenantID string, config NotificationConfig) error
	SendNotification(ctx context.Context, tenantID string, channel NotificationChannel, to []string, event string, details map[string]interface{}, maxRetry int) error
}

type SecurityModuleConfigService interface {
	GetSecurityModuleConfig(ctx context.Context, tenantID string) (SecurityModuleConfig, error)
	SetSecurityModuleConfig(ctx context.Context, tenantID string, enabled bool) error
}

// SecurityEventWebhookService handles CRUD and delivery for security event webhooks
// All methods must be robust, multi-tenant, and audit-logged
// Trigger is for manual/test delivery
type SecurityEventWebhookService interface {
	CreateWebhook(ctx context.Context, webhook SecurityEventWebhook) (SecurityEventWebhook, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]SecurityEventWebhook, error)
	DeleteWebhook(ctx context.Context, id, tenantID string) error
	TriggerWebhook(ctx context.Context, id, tenantID, eventType string, payload interface{}) error
}

type PasswordResetTokenService interface {
	CreateToken(ctx context.Context, userID string, expiresIn time.Duration) (PasswordResetToken, error)
	VerifyToken(ctx context.Context, token string) (bool, error)
	UseToken(ctx context.Context, token string, email string, password string) error
}

type RateLimitService interface {
	SetRateLimit(ctx context.Context, cfg RateLimitConfig) (RateLimitConfig, error)
	GetRateLimit(ctx context.Context, scope, scopeID string) (RateLimitConfig, error)
	DeleteRateLimit(ctx context.Context, id string) error
}

type NotificationProvider interface {
	Send(ctx context.Context, to []string, event string, details map[string]interface{}) error
	Status(ctx context.Context) (string, error)
	Name() string
}

type OwnerJWTSecretConfigService interface {
	GetOwnerJWTSecretConfig(ctx context.Context) (JWTSecretConfig, error)
}

// ConfigurationService handles various configuration types for tenants
type ConfigurationService interface {
	GetMFAConfig(ctx context.Context, tenantID string) (MFAConfig, error)
	SetMFAConfig(ctx context.Context, tenantID string, config MFAConfig) error
	GetPasswordPolicyConfig(ctx context.Context, tenantID string) (PasswordPolicyConfig, error)
	SetPasswordPolicyConfig(ctx context.Context, tenantID string, config PasswordPolicyConfig) error
	GetSessionConfig(ctx context.Context, tenantID string) (SessionConfig, error)
	SetSessionConfig(ctx context.Context, tenantID string, config SessionConfig) error
	GetNotificationChannelEnabledConfig(ctx context.Context, tenantID, channel, provider string) (NotificationChannelEnabledConfig, error)
	SetNotificationChannelEnabledConfig(ctx context.Context, config NotificationChannelEnabledConfig) error
	GetProviderConfig(ctx context.Context, tenantID, channel, provider string) (ProviderConfig, error)
	SetProviderConfig(ctx context.Context, config ProviderConfig) error
	GetOAuthConfig(ctx context.Context, tenantID string) (OAuthConfigDB, error)
	SetOAuthConfig(ctx context.Context, tenantID string, config OAuthConfigDB) error
	GetSAMLConfig(ctx context.Context, tenantID string) (SAMLConfigDB, error)
	SetSAMLConfig(ctx context.Context, tenantID string, config SAMLConfigDB) error
	GetAuthTypeConfig(ctx context.Context, tenantID string) (AuthTypeConfigDB, error)
	SetAuthTypeConfig(ctx context.Context, tenantID string, config AuthTypeConfigDB) error
	SetRateLimitConfig(ctx context.Context, config RateLimitConfig) error
}

// NotificationQueueService handles notification queueing and processing
type NotificationQueueService interface {
	AddToNotificationQueue(ctx context.Context, item NotificationQueueItem) error
	GetPendingNotificationQueue(ctx context.Context, limit int) ([]NotificationQueueItem, error)
	UpdateNotificationQueueItem(ctx context.Context, item NotificationQueueItem) error
	ProcessNotificationQueue(ctx context.Context)
}
