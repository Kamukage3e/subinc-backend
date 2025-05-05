package tenant

import "context"

// TenantStore defines prod-ready tenant storage interface for SaaS.
type TenantStore interface {
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	Create(ctx context.Context, t *Tenant) error
	Update(ctx context.Context, t *Tenant) error
	Delete(ctx context.Context, id string) error
	ListAll(ctx context.Context) ([]*Tenant, error)
}
