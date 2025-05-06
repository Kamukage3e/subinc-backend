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
}
