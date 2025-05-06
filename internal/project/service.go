package project

import (
	"context"
	"fmt"
	"time"
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
		TenantID:    input.TenantID,
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
