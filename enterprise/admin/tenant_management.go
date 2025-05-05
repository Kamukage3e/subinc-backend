package admin

import (
	"context"
	"time"
)

// Org represents an organization in the enterprise SaaS platform.
type Org struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Project represents a project within an org.
type Project struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Region represents a deployment region for multi-region SaaS.
type Region struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// OrgStore defines storage for organizations.
type OrgStore interface {
	GetByID(ctx context.Context, id string) (*Org, error)
	GetByName(ctx context.Context, name string) (*Org, error)
	Create(ctx context.Context, o *Org) error
	Update(ctx context.Context, o *Org) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Org, error)
}

// ProjectStore defines storage for projects.
type ProjectStore interface {
	GetByID(ctx context.Context, id string) (*Project, error)
	GetByOrgID(ctx context.Context, orgID string) ([]*Project, error)
	Create(ctx context.Context, p *Project) error
	Update(ctx context.Context, p *Project) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Project, error)
}

// RegionStore defines storage for regions.
type RegionStore interface {
	GetByID(ctx context.Context, id string) (*Region, error)
	GetByName(ctx context.Context, name string) (*Region, error)
	Create(ctx context.Context, r *Region) error
	Update(ctx context.Context, r *Region) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Region, error)
}
