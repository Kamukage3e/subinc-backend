package project

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)




func NewPostgresRepository(db *pgxpool.Pool) Repository {
	return &postgresRepository{db: db}
}

func (r *postgresRepository) Create(ctx context.Context, p *Project) error {
	if p == nil || p.ID == "" || p.TenantID == nil || p.Name == "" {
		return fmt.Errorf("missing required project fields")
	}
	tags, err := json.Marshal(p.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	_, err = r.db.Exec(ctx, `INSERT INTO projects (id, tenant_id, org_id, name, description, status, tags, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID, p.TenantID, p.OrgID, p.Name, p.Description, p.Status, tags, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	return nil
}

func (r *postgresRepository) Get(ctx context.Context, id string) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("missing project id")
	}
	row := r.db.QueryRow(ctx, `SELECT id, tenant_id, org_id, name, description, status, tags, created_at, updated_at FROM projects WHERE id=$1`, id)
	var p Project
	var tags []byte
	if err := row.Scan(&p.ID, &p.TenantID, &p.OrgID, &p.Name, &p.Description, &p.Status, &tags, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := json.Unmarshal(tags, &p.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}
	return &p, nil
}

func (r *postgresRepository) Update(ctx context.Context, p *Project) error {
	if p == nil || p.ID == "" {
		return fmt.Errorf("missing required project fields")
	}
	tags, err := json.Marshal(p.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}
	_, err = r.db.Exec(ctx, `UPDATE projects SET name=$1, description=$2, status=$3, tags=$4, updated_at=$5 WHERE id=$6`,
		p.Name, p.Description, p.Status, tags, p.UpdatedAt, p.ID)
	if err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}
	return nil
}

func (r *postgresRepository) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("missing project id")
	}
	_, err := r.db.Exec(ctx, `DELETE FROM projects WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	return nil
}

func (r *postgresRepository) ListByTenant(ctx context.Context, tenantID string) ([]*Project, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("missing tenant id")
	}
	rows, err := r.db.Query(ctx, `SELECT id, tenant_id, org_id, name, description, status, tags, created_at, updated_at FROM projects WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer rows.Close()
	var projects []*Project
	for rows.Next() {
		var p Project
		var tags []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.OrgID, &p.Name, &p.Description, &p.Status, &tags, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}
		if err := json.Unmarshal(tags, &p.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
		projects = append(projects, &p)
	}
	return projects, nil
}

func (r *postgresRepository) ListByOrg(ctx context.Context, orgID string) ([]*Project, error) {
	if orgID == "" {
		return nil, fmt.Errorf("missing org id")
	}
	rows, err := r.db.Query(ctx, `SELECT id, tenant_id, org_id, name, description, status, tags, created_at, updated_at FROM projects WHERE org_id=$1`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer rows.Close()
	var projects []*Project
	for rows.Next() {
		var p Project
		var tags []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.OrgID, &p.Name, &p.Description, &p.Status, &tags, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan project: %w", err)
		}
		if err := json.Unmarshal(tags, &p.Tags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
		projects = append(projects, &p)
	}
	return projects, nil
}
