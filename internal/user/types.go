package user

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

// User represents a real SaaS user. All fields are required for prod.
type User struct {
	ID            string            `json:"id" db:"id"`                         // UUID, unique per user
	TenantID      string            `json:"tenant_id" db:"tenant_id"`           // Tenant scoping for multi-tenant SaaS
	Username      string            `json:"username" db:"username"`             // Unique username
	Email         string            `json:"email" db:"email"`                   // Unique email
	PasswordHash  string            `json:"-" db:"password_hash"`               // Argon2id hash, never exposed
	Roles         []string          `json:"roles" db:"roles"`                   // User roles (RBAC)
	Attributes    map[string]string `json:"attributes" db:"attributes"`         // Arbitrary user metadata
	CreatedAt     time.Time         `json:"created_at" db:"created_at"`         // ISO8601 UTC
	UpdatedAt     time.Time         `json:"updated_at" db:"updated_at"`         // ISO8601 UTC
	EmailVerified bool              `json:"email_verified" db:"email_verified"` // Email verification status
}

// RefreshToken represents a JWT refresh token for a user session.
// All tokens are DB-backed, secure, and time-limited for SaaS.
// Table: refresh_tokens
// PK: TokenID (UUID)
type RefreshToken struct {
	TokenID   string    `json:"token_id" db:"token_id"`     // UUID
	UserID    string    `json:"user_id" db:"user_id"`       // User foreign key
	TenantID  string    `json:"tenant_id" db:"tenant_id"`   // Tenant scoping
	Token     string    `json:"token" db:"token"`           // JWT string
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"` // Expiry (UTC)
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Creation (UTC)
	Revoked   bool      `json:"revoked" db:"revoked"`       // Revocation status
}

// PasswordResetToken represents a secure, time-limited password reset token.
// Table: password_reset_tokens
// PK: Token (UUID)
type PasswordResetToken struct {
	Token     string    `json:"token" db:"token"`           // UUID
	UserID    string    `json:"user_id" db:"user_id"`       // User foreign key
	TenantID  string    `json:"tenant_id" db:"tenant_id"`   // Tenant scoping
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"` // Expiry (UTC)
	Used      bool      `json:"used" db:"used"`             // Usage status
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Creation (UTC)
}

// EmailVerificationToken represents a secure, time-limited email verification token.
// Table: email_verification_tokens
// PK: Token (UUID)
type EmailVerificationToken struct {
	Token     string    `json:"token" db:"token"`           // UUID
	UserID    string    `json:"user_id" db:"user_id"`       // User foreign key
	TenantID  string    `json:"tenant_id" db:"tenant_id"`   // Tenant scoping
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"` // Expiry (UTC)
	Used      bool      `json:"used" db:"used"`             // Usage status
	CreatedAt time.Time `json:"created_at" db:"created_at"` // Creation (UTC)
}

// UserHandler handles all user-related HTTP endpoints. Modular, SaaS-grade, handler-based routing.
type UserHandler struct {
	store         UserStore              // Backing store (Postgres, etc.)
	secrets       secrets.SecretsManager // Secrets manager (cloud-native)
	jwtSecretName string                 // Name of JWT secret in secrets manager
	emailSender   EmailSender            // Email sender (provider abstraction)
}

// PostgresUserStore implements UserStore using PostgreSQL. All queries are parameterized and safe for SaaS.
type PostgresUserStore struct {
	DB *pgxpool.Pool // Connection pool
}
