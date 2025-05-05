package user_management

import (
	"context"
	"time"
)

// SCIMUser represents a user provisioned via SCIM or delegated admin.
type SCIMUser struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	Username  string    `json:"username" db:"username"`
	Email     string    `json:"email" db:"email"`
	Active    bool      `json:"active" db:"active"`
	Roles     []string  `json:"roles" db:"roles"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SCIMStore defines storage for SCIM users and provisioning.
type SCIMStore interface {
	CreateUser(ctx context.Context, u *SCIMUser) error
	GetUserByID(ctx context.Context, id string) (*SCIMUser, error)
	GetUserByUsername(ctx context.Context, username string) (*SCIMUser, error)
	UpdateUser(ctx context.Context, u *SCIMUser) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, orgID string) ([]*SCIMUser, error)
}
