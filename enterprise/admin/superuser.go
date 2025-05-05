package admin

import (
	"context"
	"time"
)

// Superuser represents a privileged admin user for enterprise operations.
type Superuser struct {
	ID        string    `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password_hash"`
	Roles     []string  `json:"roles" db:"roles"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SuperuserStore defines storage for superusers (enterprise-only).
type SuperuserStore interface {
	GetByUsername(ctx context.Context, username string) (*Superuser, error)
	GetByID(ctx context.Context, id string) (*Superuser, error)
	Create(ctx context.Context, u *Superuser) error
	Update(ctx context.Context, u *Superuser) error
	Delete(ctx context.Context, id string) error
	AssignRole(ctx context.Context, id string, role string) error
	RemoveRole(ctx context.Context, id string, role string) error
	List(ctx context.Context) ([]*Superuser, error)
}
