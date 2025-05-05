package project

import (
	"context"
	"time"
)

// Project represents a project in the SaaS platform.
type Project struct {
	ID        string    `json:"id" db:"id"`
	OrgID     string    `json:"org_id" db:"org_id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"` // JSON blob for project settings/policies
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ProjectStore defines storage for projects and policies.
type ProjectStore interface {
	Create(ctx context.Context, p *Project) error
	GetByID(ctx context.Context, id string) (*Project, error)
	GetByOrgID(ctx context.Context, orgID string) ([]*Project, error)
	Update(ctx context.Context, p *Project) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Project, error)
}
