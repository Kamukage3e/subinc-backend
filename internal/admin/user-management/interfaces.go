package user_management

import (
	"context"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

type UserService interface {
	CreateUser(ctx context.Context, user User) (User, error)
	UpdateUser(ctx context.Context, user User) (User, error)
	DeleteUser(ctx context.Context, id string) error
	GetUser(ctx context.Context, id string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	ListUsers(ctx context.Context, status string, page, pageSize int) ([]User, error)
}

type UserProfileService interface {
	CreateProfile(ctx context.Context, profile UserProfile) (UserProfile, error)
	UpdateProfile(ctx context.Context, profile UserProfile) (UserProfile, error)
	GetProfile(ctx context.Context, userID string) (UserProfile, error)
}

type UserSettingsService interface {
	GetSettings(ctx context.Context, userID string) (UserSettings, error)
	UpdateSettings(ctx context.Context, userID, settings string) error
}

type UserSessionService interface {
	CreateSession(ctx context.Context, session UserSession) (UserSession, error)
	DeleteSession(ctx context.Context, id string) error
	GetSession(ctx context.Context, id string) (UserSession, error)
	ListSessions(ctx context.Context, userID string, page, pageSize int) ([]UserSession, error)
}

type UserAuditLogger = security_management.AuditLogger

type UserAuditLogService interface {
	CreateAuditLog(ctx context.Context, log UserAuditLog) (UserAuditLog, error)
	ListAuditLogs(ctx context.Context, userID, actorID, action string, page, pageSize int) ([]UserAuditLog, error)
}
