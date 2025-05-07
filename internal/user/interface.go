package user

import "context"

// UserStore defines the contract for user storage in SaaS. All methods are required for production.
type UserStore interface {
	// User CRUD
	GetByUsername(ctx context.Context, username string) (*User, error)    // Get user by username
	GetByID(ctx context.Context, id string) (*User, error)                // Get user by ID
	Create(ctx context.Context, u *User) error                            // Create new user
	Update(ctx context.Context, u *User) error                            // Update user
	Delete(ctx context.Context, id string) error                          // Delete user
	ListByTenantID(ctx context.Context, tenantID string) ([]*User, error) // List users by tenant

	// Refresh token management (JWT session rotation)
	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error

	// Password reset token management
	CreatePasswordResetToken(ctx context.Context, t *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	MarkPasswordResetTokenUsed(ctx context.Context, token string) error

	// Email verification token management
	CreateEmailVerificationToken(ctx context.Context, t *EmailVerificationToken) error
	GetEmailVerificationToken(ctx context.Context, token string) (*EmailVerificationToken, error)
	MarkEmailVerificationTokenUsed(ctx context.Context, token string) error

	GetByEmail(ctx context.Context, email string) (*User, error) // Get user by email
}

// EmailSender defines the interface for sending emails via a real provider. No dummy implementations allowed.
type EmailSender interface {
	SendResetEmail(to, token string) error
	SendVerificationEmail(to, token string) error
	SendDeviceLoginNotification(to, deviceName, ip, userAgent string) error
	SendDeviceChangeNotification(to, deviceName, changeType string) error
}

// UserDeviceStore defines the contract for device/session storage in SaaS. All methods are required for production.
type UserDeviceStore interface {
	CreateDevice(ctx context.Context, d *UserDevice) error
	UpdateDevice(ctx context.Context, d *UserDevice) error
	GetDeviceByID(ctx context.Context, deviceID string) (*UserDevice, error)
	ListDevicesByUserID(ctx context.Context, userID string) ([]*UserDevice, error)
	RevokeDevice(ctx context.Context, deviceID string) error
	RevokeAllDevicesForUser(ctx context.Context, userID string) error
}

// UserOrgProjectRoleStore defines the contract for cross-org/project role/permission storage in SaaS. All methods are required for production.
type UserOrgProjectRoleStore interface {
	CreateRole(ctx context.Context, r *UserOrgProjectRole) error
	UpdateRole(ctx context.Context, r *UserOrgProjectRole) error
	DeleteRole(ctx context.Context, id string) error
	GetRoleByID(ctx context.Context, id string) (*UserOrgProjectRole, error)
	ListRolesByUser(ctx context.Context, userID string) ([]*UserOrgProjectRole, error)
	ListRolesByOrg(ctx context.Context, orgID string) ([]*UserOrgProjectRole, error)
	ListRolesByProject(ctx context.Context, projectID string) ([]*UserOrgProjectRole, error)
	FindRole(ctx context.Context, userID, orgID, projectID, role string) (*UserOrgProjectRole, error)
}
