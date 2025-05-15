package user_management

import (
	"context"
)

// UserService handles core user operations
type UserService interface {
	CreateUser(ctx context.Context, user User) (User, error)
	UpdateUser(ctx context.Context, user User) (User, error)
	DeleteUser(ctx context.Context, id string) error
	GetUser(ctx context.Context, id string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	ListUsers(ctx context.Context, status string, page, pageSize int) ([]User, error)
}

// UserProfileService handles user profile operations
type UserProfileService interface {
	CreateProfile(ctx context.Context, profile UserProfile) (UserProfile, error)
	UpdateProfile(ctx context.Context, profile UserProfile) (UserProfile, error)
	GetProfile(ctx context.Context, userID string) (UserProfile, error)
}

// UserSettingsService handles user settings operations
type UserSettingsService interface {
	GetSettings(ctx context.Context, userID string) (map[string]interface{}, error)
	UpdateSettings(ctx context.Context, userID string, settings map[string]interface{}) error
}

// UserAuditLogService handles audit logging for user actions
type UserAuditLogService interface {
	CreateAuditLog(ctx context.Context, log UserAuditLog) (UserAuditLog, error)
	ListAuditLogs(ctx context.Context, userID, actorID, action string, page, pageSize int) ([]UserAuditLog, error)
}

// OrgProjectUserService handles membership and invites for orgs and projects
type OrgProjectUserService interface {
	// Org membership
	AddUserToOrg(ctx context.Context, orgID, userID, invitedBy, role string) error
	RemoveUserFromOrg(ctx context.Context, orgID, userID string) error
	ListOrgUsers(ctx context.Context, orgID string, page, pageSize int) ([]User, error)
	InviteUserToOrg(ctx context.Context, orgID, email, invitedBy, role string) error

	// Project membership
	AddUserToProject(ctx context.Context, projectID, userID, invitedBy, role string) error
	RemoveUserFromProject(ctx context.Context, projectID, userID string) error
	ListProjectUsers(ctx context.Context, projectID string, page, pageSize int) ([]User, error)
	InviteUserToProject(ctx context.Context, projectID, email, invitedBy, role string) error
}
