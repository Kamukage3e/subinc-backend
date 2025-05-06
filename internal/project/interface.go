package project

import "context"

type Service interface {
	Create(ctx context.Context, input CreateProjectInput) (CreateProjectOutput, error)
	Get(ctx context.Context, input GetProjectInput) (GetProjectOutput, error)
	Update(ctx context.Context, input UpdateProjectInput) (UpdateProjectOutput, error)
	Delete(ctx context.Context, input DeleteProjectInput) (DeleteProjectOutput, error)
	ListByTenant(ctx context.Context, input ListProjectsByTenantInput) (ListProjectsOutput, error)
	ListByOrg(ctx context.Context, input ListProjectsByOrgInput) (ListProjectsOutput, error)
}

type Repository interface {
	Create(ctx context.Context, p *Project) error
	Get(ctx context.Context, id string) (*Project, error)
	Update(ctx context.Context, p *Project) error
	Delete(ctx context.Context, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*Project, error)
	ListByOrg(ctx context.Context, orgID string) ([]*Project, error)
}
