package security_management

import "context"

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
