package project

import "time"

// Project represents a real SaaS project. All fields are required for prod.
type Project struct {
	ID          string            `json:"id" db:"id"`
	TenantID    string            `json:"tenant_id" db:"tenant_id"`
	OrgID       *string           `json:"org_id,omitempty" db:"org_id"` // Optional
	Name        string            `json:"name" db:"name"`
	Description string            `json:"description" db:"description"`
	Status      string            `json:"status" db:"status"`
	Tags        map[string]string `json:"tags" db:"tags"`
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
}
