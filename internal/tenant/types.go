package tenant

import (
	"time"
)

// Tenant represents a real SaaS tenant/org. All fields are required for prod.
type Tenant struct {
	ID        string    `json:"id" db:"id"`                 // UUID, unique per tenant
	Name      string    `json:"name" db:"name"`             // Unique tenant/org name
	Settings  string    `json:"settings" db:"settings"`     // JSON blob for org settings/policies
	CreatedAt time.Time `json:"created_at" db:"created_at"` // ISO8601 UTC
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"` // ISO8601 UTC
}

// TenantHandler handles tenant-related endpoints. Modular, SaaS-grade, handler-based routing.
type TenantHandler struct {
	store TenantStore // Backing store (Postgres, etc.)
}
