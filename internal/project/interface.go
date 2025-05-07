package project

import (
	"context"

	"github.com/subinc/subinc-backend/internal/user"
)

type Service interface {
	Create(ctx context.Context, input CreateProjectInput) (CreateProjectOutput, error)
	Get(ctx context.Context, input GetProjectInput) (GetProjectOutput, error)
	Update(ctx context.Context, input UpdateProjectInput) (UpdateProjectOutput, error)
	Delete(ctx context.Context, input DeleteProjectInput) (DeleteProjectOutput, error)
	ListByTenant(ctx context.Context, input ListProjectsByTenantInput) (ListProjectsOutput, error)
	ListByOrg(ctx context.Context, input ListProjectsByOrgInput) (ListProjectsOutput, error)
	AssignProjectOwner(ctx context.Context, userID, projectID string) error
	TransferProjectOwner(ctx context.Context, actorID, projectID, newOwnerID string) error
	TransferUserToProject(ctx context.Context, actorID, userID, fromProjectID, toProjectID string) error
	ListProjectUsers(ctx context.Context, actorID, projectID string) ([]*user.UserOrgProjectRole, error)
	AddUserToProject(ctx context.Context, actorID, projectID, userID, role string, perms []string) error
	RemoveUserFromProject(ctx context.Context, actorID, projectID, userID string) error
}

type Repository interface {
	Create(ctx context.Context, p *Project) error
	Get(ctx context.Context, id string) (*Project, error)
	Update(ctx context.Context, p *Project) error
	Delete(ctx context.Context, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]*Project, error)
	ListByOrg(ctx context.Context, orgID string) ([]*Project, error)
}
