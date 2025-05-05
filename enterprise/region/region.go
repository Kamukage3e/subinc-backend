 package region

import (
	"context"
	"time"
)

// Region represents a deployment region for multi-region SaaS.
type Region struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Geo       string    `json:"geo" db:"geo"` // e.g., us-east-1, eu-west-1
	Active    bool      `json:"active" db:"active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RegionStore defines storage for regions and failover/geo policies.
type RegionStore interface {
	Create(ctx context.Context, r *Region) error
	GetByID(ctx context.Context, id string) (*Region, error)
	GetByName(ctx context.Context, name string) (*Region, error)
	List(ctx context.Context) ([]*Region, error)
	Update(ctx context.Context, r *Region) error
	Delete(ctx context.Context, id string) error
} 