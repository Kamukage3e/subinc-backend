package project

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/user"
)

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, input CreateProjectInput) (CreateProjectOutput, error) {
	if input.ID == "" || input.TenantID == "" || input.Name == "" {
		return CreateProjectOutput{}, fmt.Errorf("missing required fields")
	}
	p := &Project{
		ID:          input.ID,
		TenantID:    &input.TenantID,
		OrgID:       input.OrgID,
		Name:        input.Name,
		Description: input.Description,
		Status:      input.Status,
		Tags:        input.Tags,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return CreateProjectOutput{}, err
	}
	return CreateProjectOutput{Project: p}, nil
}

func (s *service) Get(ctx context.Context, input GetProjectInput) (GetProjectOutput, error) {
	if input.ID == "" {
		return GetProjectOutput{}, fmt.Errorf("missing project id")
	}
	p, err := s.repo.Get(ctx, input.ID)
	if err != nil {
		return GetProjectOutput{}, err
	}
	return GetProjectOutput{Project: p}, nil
}

func (s *service) Update(ctx context.Context, input UpdateProjectInput) (UpdateProjectOutput, error) {
	if input.ID == "" {
		return UpdateProjectOutput{}, fmt.Errorf("missing project id")
	}
	p, err := s.repo.Get(ctx, input.ID)
	if err != nil {
		return UpdateProjectOutput{}, err
	}
	if input.Name != "" {
		p.Name = input.Name
	}
	if input.Description != "" {
		p.Description = input.Description
	}
	if input.Status != "" {
		p.Status = input.Status
	}
	if input.Tags != nil {
		p.Tags = input.Tags
	}
	p.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, p); err != nil {
		return UpdateProjectOutput{}, err
	}
	return UpdateProjectOutput{Project: p}, nil
}

func (s *service) Delete(ctx context.Context, input DeleteProjectInput) (DeleteProjectOutput, error) {
	if input.ID == "" {
		return DeleteProjectOutput{}, fmt.Errorf("missing project id")
	}
	if err := s.repo.Delete(ctx, input.ID); err != nil {
		return DeleteProjectOutput{}, err
	}
	return DeleteProjectOutput{Success: true}, nil
}

func (s *service) ListByTenant(ctx context.Context, input ListProjectsByTenantInput) (ListProjectsOutput, error) {
	if input.TenantID == "" {
		return ListProjectsOutput{}, fmt.Errorf("missing tenant id")
	}
	projects, err := s.repo.ListByTenant(ctx, input.TenantID)
	if err != nil {
		return ListProjectsOutput{}, err
	}
	return ListProjectsOutput{Projects: projects}, nil
}

func (s *service) ListByOrg(ctx context.Context, input ListProjectsByOrgInput) (ListProjectsOutput, error) {
	if input.OrgID == "" {
		return ListProjectsOutput{}, fmt.Errorf("missing org id")
	}
	projects, err := s.repo.ListByOrg(ctx, input.OrgID)
	if err != nil {
		return ListProjectsOutput{}, err
	}
	return ListProjectsOutput{Projects: projects}, nil
}

func (s *service) AssignProjectOwner(ctx context.Context, userID, projectID string) error {
	if userID == "" || projectID == "" {
		return fmt.Errorf("missing userID or projectID")
	}
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      userID,
		ProjectID:   &projectID,
		Role:        "owner",
		Permissions: []string{"project:admin", "project:write", "project:read"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	userStore, ok := s.repo.(interface {
		CreateRole(ctx context.Context, r *user.UserOrgProjectRole) error
	})
	if !ok {
		return fmt.Errorf("repo does not support CreateRole")
	}
	return userStore.CreateRole(ctx, role)
}

func (s *service) TransferProjectOwner(ctx context.Context, actorID, projectID, newOwnerID string) error {
	if actorID == "" || projectID == "" || newOwnerID == "" {
		return fmt.Errorf("missing required fields")
	}
	userStore, ok := s.repo.(interface {
		FindRole(ctx context.Context, userID, orgID, projectID, role string) (*user.UserOrgProjectRole, error)
		DeleteRole(ctx context.Context, id string) error
		CreateRole(ctx context.Context, r *user.UserOrgProjectRole) error
	})
	if !ok {
		return fmt.Errorf("repo does not support role management")
	}
	// Only current owner can transfer
	ownerRole, err := userStore.FindRole(ctx, actorID, "", projectID, "owner")
	if err != nil || ownerRole == nil {
		return fmt.Errorf("only current owner can transfer project")
	}
	// Remove old owner role
	if err := userStore.DeleteRole(ctx, ownerRole.ID); err != nil {
		return fmt.Errorf("failed to remove old owner role: %w", err)
	}
	// Assign new owner
	role := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      newOwnerID,
		ProjectID:   &projectID,
		Role:        "owner",
		Permissions: []string{"project:admin", "project:write", "project:read"},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := userStore.CreateRole(ctx, role); err != nil {
		return fmt.Errorf("failed to assign new owner: %w", err)
	}
	return nil
}

func (s *service) TransferUserToProject(ctx context.Context, actorID, userID, fromProjectID, toProjectID string) error {
	if actorID == "" || userID == "" || fromProjectID == "" || toProjectID == "" {
		return fmt.Errorf("missing required fields")
	}
	userStore, ok := s.repo.(interface {
		FindRole(ctx context.Context, userID, orgID, projectID, role string) (*user.UserOrgProjectRole, error)
		DeleteRole(ctx context.Context, id string) error
		CreateRole(ctx context.Context, r *user.UserOrgProjectRole) error
		ListRolesByUser(ctx context.Context, userID string) ([]*user.UserOrgProjectRole, error)
	})
	if !ok {
		return fmt.Errorf("repo does not support role management")
	}
	// Only owner/admin of fromProjectID can transfer
	adminRole, err := userStore.FindRole(ctx, actorID, "", fromProjectID, "owner")
	if err != nil || adminRole == nil {
		adminRole, err = userStore.FindRole(ctx, actorID, "", fromProjectID, "admin")
		if err != nil || adminRole == nil {
			return fmt.Errorf("only project owner/admin can transfer users")
		}
	}
	// Find all roles for user in fromProjectID
	roles, err := userStore.ListRolesByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to list user roles: %w", err)
	}
	var transferred bool
	for _, r := range roles {
		if r.ProjectID != nil && *r.ProjectID == fromProjectID {
			// Remove from old project
			if err := userStore.DeleteRole(ctx, r.ID); err != nil {
				return fmt.Errorf("failed to remove user from old project: %w", err)
			}
			// Assign to new project with same role/permissions
			newRole := &user.UserOrgProjectRole{
				ID:          uuid.NewString(),
				UserID:      userID,
				ProjectID:   &toProjectID,
				Role:        r.Role,
				Permissions: r.Permissions,
				CreatedAt:   time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			}
			if err := userStore.CreateRole(ctx, newRole); err != nil {
				return fmt.Errorf("failed to assign user to new project: %w", err)
			}
			transferred = true
		}
	}
	if !transferred {
		return fmt.Errorf("user has no roles in fromProjectID")
	}
	return nil
}

func (s *service) ListProjectUsers(ctx context.Context, actorID, projectID string) ([]*user.UserOrgProjectRole, error) {
	if actorID == "" || projectID == "" {
		return nil, fmt.Errorf("missing required fields")
	}
	userStore, ok := s.repo.(interface {
		FindRole(ctx context.Context, userID, orgID, projectID, role string) (*user.UserOrgProjectRole, error)
		ListRolesByProject(ctx context.Context, projectID string) ([]*user.UserOrgProjectRole, error)
	})
	if !ok {
		return nil, fmt.Errorf("repo does not support role management")
	}
	adminRole, err := userStore.FindRole(ctx, actorID, "", projectID, "owner")
	if err != nil || adminRole == nil {
		adminRole, err = userStore.FindRole(ctx, actorID, "", projectID, "admin")
		if err != nil || adminRole == nil {
			return nil, fmt.Errorf("only project owner/admin can list users")
		}
	}
	return userStore.ListRolesByProject(ctx, projectID)
}

func (s *service) AddUserToProject(ctx context.Context, actorID, projectID, userID, role string, perms []string) error {
	if actorID == "" || projectID == "" || userID == "" || role == "" {
		return fmt.Errorf("missing required fields")
	}
	userStore, ok := s.repo.(interface {
		FindRole(ctx context.Context, userID, orgID, projectID, role string) (*user.UserOrgProjectRole, error)
		CreateRole(ctx context.Context, r *user.UserOrgProjectRole) error
	})
	if !ok {
		return fmt.Errorf("repo does not support role management")
	}
	adminRole, err := userStore.FindRole(ctx, actorID, "", projectID, "owner")
	if err != nil || adminRole == nil {
		adminRole, err = userStore.FindRole(ctx, actorID, "", projectID, "admin")
		if err != nil || adminRole == nil {
			return fmt.Errorf("only project owner/admin can add users")
		}
	}
	newRole := &user.UserOrgProjectRole{
		ID:          uuid.NewString(),
		UserID:      userID,
		ProjectID:   &projectID,
		Role:        role,
		Permissions: perms,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	return userStore.CreateRole(ctx, newRole)
}

func (s *service) RemoveUserFromProject(ctx context.Context, actorID, projectID, userID string) error {
	if actorID == "" || projectID == "" || userID == "" {
		return fmt.Errorf("missing required fields")
	}
	userStore, ok := s.repo.(interface {
		FindRole(ctx context.Context, userID, orgID, projectID, role string) (*user.UserOrgProjectRole, error)
		DeleteRole(ctx context.Context, id string) error
		ListRolesByUser(ctx context.Context, userID string) ([]*user.UserOrgProjectRole, error)
	})
	if !ok {
		return fmt.Errorf("repo does not support role management")
	}
	adminRole, err := userStore.FindRole(ctx, actorID, "", projectID, "owner")
	if err != nil || adminRole == nil {
		adminRole, err = userStore.FindRole(ctx, actorID, "", projectID, "admin")
		if err != nil || adminRole == nil {
			return fmt.Errorf("only project owner/admin can remove users")
		}
	}
	roles, err := userStore.ListRolesByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to list user roles: %w", err)
	}
	var removed bool
	for _, r := range roles {
		if r.ProjectID != nil && *r.ProjectID == projectID {
			if err := userStore.DeleteRole(ctx, r.ID); err != nil {
				return fmt.Errorf("failed to remove user from project: %w", err)
			}
			removed = true
		}
	}
	if !removed {
		return fmt.Errorf("user has no roles in project")
	}
	return nil
}
