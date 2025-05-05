package admin

import "context"

// AdminUserStore defines storage for admin users.
type AdminUserStore interface {
	GetByUsername(ctx context.Context, username string) (*AdminUser, error)
	GetByID(ctx context.Context, id string) (*AdminUser, error)
	Create(ctx context.Context, u *AdminUser) error
	Update(ctx context.Context, u *AdminUser) error
	Delete(ctx context.Context, id string) error
}

// AdminRoleStore defines storage for admin roles.
type AdminRoleStore interface {
	GetByName(ctx context.Context, name string) (*AdminRole, error)
	GetByID(ctx context.Context, id string) (*AdminRole, error)
	Create(ctx context.Context, r *AdminRole) error
	Update(ctx context.Context, r *AdminRole) error
	Delete(ctx context.Context, id string) error
}

// AdminPermissionStore defines storage for admin permissions.
type AdminPermissionStore interface {
	GetByName(ctx context.Context, name string) (*AdminPermission, error)
	GetByID(ctx context.Context, id string) (*AdminPermission, error)
	Create(ctx context.Context, p *AdminPermission) error
	Update(ctx context.Context, p *AdminPermission) error
	Delete(ctx context.Context, id string) error
}
