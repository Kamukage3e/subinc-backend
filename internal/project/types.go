package project

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type service struct {
	repo Repository
}

type Deps struct {
	ProjectHandler *Handler
}

type Handler struct {
	service Service
	log     *logger.Logger
}

// Input/Output types for RORO pattern
type CreateProjectInput struct {
	ID          string
	TenantID    string
	OrgID       *string
	Name        string
	Description string
	Status      string
	Tags        map[string]string
}
type CreateProjectOutput struct {
	Project *Project
}
type GetProjectInput struct {
	ID string
}
type GetProjectOutput struct {
	Project *Project
}
type UpdateProjectInput struct {
	ID          string
	Name        string
	Description string
	Status      string
	Tags        map[string]string
}
type UpdateProjectOutput struct {
	Project *Project
}
type DeleteProjectInput struct {
	ID string
}
type DeleteProjectOutput struct {
	Success bool
}
type ListProjectsByTenantInput struct {
	TenantID string
}
type ListProjectsByOrgInput struct {
	OrgID string
}
type ListProjectsOutput struct {
	Projects []*Project
}

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

type postgresRepository struct {
	db *pgxpool.Pool
}
