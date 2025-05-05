package organization

import (
	"context"
	"time"
)

// Organization represents a top-level org in the SaaS platform.
type Organization struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"` // JSON blob for org settings/policies
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// OrganizationStore defines storage for organizations and policies.
type OrganizationStore interface {
	Create(ctx context.Context, o *Organization) error
	GetByID(ctx context.Context, id string) (*Organization, error)
	GetByName(ctx context.Context, name string) (*Organization, error)
	Update(ctx context.Context, o *Organization) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Organization, error)
}
