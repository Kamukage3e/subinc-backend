package user

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/subinc/subinc-backend/internal/cost/repository"
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
	MFASecret     string            `json:"-" db:"mfa_secret"`                  // TOTP secret (base32)
	MFAEnabled    bool              `json:"mfa_enabled" db:"mfa_enabled"`       // Is MFA enabled
	BackupCodes   []string          `json:"-" db:"backup_codes"`                // One-time backup codes
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

// UserDevice represents a device/session for a user (SaaS-grade, prod-ready)
type UserDevice struct {
	DeviceID       string    `json:"device_id" db:"device_id"`               // UUID
	UserID         string    `json:"user_id" db:"user_id"`                   // User foreign key
	RefreshTokenID string    `json:"refresh_token_id" db:"refresh_token_id"` // Refresh token foreign key
	UserAgent      string    `json:"user_agent" db:"user_agent"`             // Browser/mobile agent
	IP             string    `json:"ip" db:"ip"`                             // Last known IP
	CreatedAt      time.Time `json:"created_at" db:"created_at"`             // Session start
	LastSeen       time.Time `json:"last_seen" db:"last_seen"`               // Last activity
	Revoked        bool      `json:"revoked" db:"revoked"`                   // Session revoked
	Name           string    `json:"name" db:"name"`                         // Friendly device name
}

// UserOrgProjectRole represents a user's role/permissions at org/project/global scope (SaaS, prod-ready)
type UserOrgProjectRole struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	OrgID       *string   `json:"org_id,omitempty" db:"org_id"`
	ProjectID   *string   `json:"project_id,omitempty" db:"project_id"`
	Role        string    `json:"role" db:"role"`
	Permissions []string  `json:"permissions" db:"permissions"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// UserRolesPermissions represents all roles/permissions for a user across orgs/projects/global (for admin/global listing)
type UserRolesPermissions struct {
	UserID   string               `json:"user_id"`
	Username string               `json:"username"`
	Email    string               `json:"email"`
	Roles    []UserOrgProjectRole `json:"roles"`
}

// UserHandler handles all user-related HTTP endpoints. Modular, SaaS-grade, handler-based routing.
type UserHandler struct {
	store         UserStore
	secrets       secrets.SecretsManager
	jwtSecretName string
	emailSender   EmailSender
	billingRepo   repository.BillingRepository
}

// PostgresUserStore implements UserStore using PostgreSQL. All queries are parameterized and safe for SaaS.
type PostgresUserStore struct {
	DB *pgxpool.Pool // Connection pool
}

// TOTP MFA helpers for User
func (u *User) IsMFAEnabled() bool {
	return u.MFAEnabled && u.MFASecret != ""
}

// SetMFASecret sets the TOTP secret and enables MFA
func (u *User) SetMFASecret(secret string) {
	u.MFASecret = secret
	u.MFAEnabled = true
}

// DisableMFA disables MFA and clears secret/backup codes
func (u *User) DisableMFA() {
	u.MFASecret = ""
	u.MFAEnabled = false
	u.BackupCodes = nil
}

// SetBackupCodes sets backup codes (one-time use)
func (u *User) SetBackupCodes(codes []string) {
	u.BackupCodes = codes
}

// UseBackupCode marks a backup code as used (removes it)
func (u *User) UseBackupCode(code string) bool {
	for i, c := range u.BackupCodes {
		if c == code {
			u.BackupCodes = append(u.BackupCodes[:i], u.BackupCodes[i+1:]...)
			return true
		}
	}
	return false
}
