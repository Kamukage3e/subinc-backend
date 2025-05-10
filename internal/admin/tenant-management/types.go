package tenant_management

import "time"

// Tenant represents a SaaS tenant/org
// All fields are required for production
// Settings is a JSON blob for org settings/policies
// CreatedAt/UpdatedAt are UTC
// ID is UUID
// Name is unique per tenant
type Tenant struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TenantSettings is a map for settings JSON
// Used for settings endpoints
type TenantSettings map[string]interface{}

// TenantFilter for search, sort, pagination
// Used by list/search endpoints
type TenantFilter struct {
	Query   string
	SortBy  string
	SortDir string
	Limit   int
	Offset  int
}
