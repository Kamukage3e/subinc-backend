package integrations

import (
	"context"
	"time"
)

// Integration represents a 3rd-party integration configuration.
type Integration struct {
	ID        string    `json:"id" db:"id"`
	Type      string    `json:"type" db:"type"`     // e.g., okta, slack, workday
	Config    string    `json:"config" db:"config"` // JSON config blob
	Enabled   bool      `json:"enabled" db:"enabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IntegrationStore defines storage for integrations.
type IntegrationStore interface {
	Create(ctx context.Context, i *Integration) error
	GetByID(ctx context.Context, id string) (*Integration, error)
	List(ctx context.Context, integrationType string) ([]*Integration, error)
	Update(ctx context.Context, i *Integration) error
	Delete(ctx context.Context, id string) error
	Enable(ctx context.Context, id string) error
	Disable(ctx context.Context, id string) error
}
