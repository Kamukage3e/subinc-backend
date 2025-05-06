package tenant

import "context"

// TenantStore defines prod-ready tenant storage interface for SaaS.
type TenantStore interface {
	GetByID(ctx context.Context, id string) (*Tenant, error)     // Get tenant by ID
	GetByName(ctx context.Context, name string) (*Tenant, error) // Get tenant by name
	Create(ctx context.Context, t *Tenant) error                 // Create new tenant
	Update(ctx context.Context, t *Tenant) error                 // Update tenant
	Delete(ctx context.Context, id string) error                 // Delete tenant
	ListAll(ctx context.Context) ([]*Tenant, error)              // List all tenants
}
