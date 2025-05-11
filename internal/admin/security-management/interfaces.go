package security_management

import (
	"context"
	"time"
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
}

type PasswordService interface {
	ResetUserPassword(ctx context.Context, userID, newPassword string) error
}

type SessionService interface {
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
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
}

type NotificationService interface {
	GetNotificationConfig(ctx context.Context, tenantID string) (NotificationConfig, error)
	UpdateNotificationConfig(ctx context.Context, config NotificationConfig) error
	SendNotification(ctx context.Context, tenantID string, event string, details map[string]interface{}) error
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
	VerifyToken(ctx context.Context, token string) (PasswordResetToken, error)
	UseToken(ctx context.Context, token string) error
}

type RateLimitService interface {
	SetRateLimit(ctx context.Context, cfg RateLimitConfig) (RateLimitConfig, error)
	GetRateLimit(ctx context.Context, scope, scopeID string) (RateLimitConfig, error)
	DeleteRateLimit(ctx context.Context, id string) error
}
