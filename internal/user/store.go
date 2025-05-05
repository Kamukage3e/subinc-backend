package user

import "context"

// UserStore defines prod-ready user storage interface for SaaS.
type UserStore interface {
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	Create(ctx context.Context, u *User) error
	Update(ctx context.Context, u *User) error
	Delete(ctx context.Context, id string) error
	ListByTenantID(ctx context.Context, tenantID string) ([]*User, error)
}
