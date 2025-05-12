package project_management

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// DB store implementations for project-management admin module will go here.

// --- ProjectService ---
func (s *PostgresStore) CreateProject(ctx context.Context, project Project) (Project, error) {
	if project.ID == "" {
		project.ID = generateUUID()
	}
	project.CreatedAt = time.Now()
	project.UpdatedAt = project.CreatedAt
	_, err := s.DB.Exec(ctx, `INSERT INTO projects (id, org_id, name, description, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		project.ID, project.OrgID, project.Name, project.Description, project.Status, project.CreatedAt, project.UpdatedAt)
	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("project", project))
		return Project{}, wrapDBErr("create_project", err)
	}
	return project, nil
}

func (s *PostgresStore) UpdateProject(ctx context.Context, project Project) (Project, error) {
	project.UpdatedAt = time.Now()
	res, err := s.DB.Exec(ctx, `UPDATE projects SET name=$1, description=$2, status=$3, updated_at=$4 WHERE id=$5`,
		project.Name, project.Description, project.Status, project.UpdatedAt, project.ID)
	if err != nil {
		logger.LogError("UpdateProject: failed", logger.ErrorField(err), logger.Any("project", project))
		return Project{}, wrapDBErr("update_project", err)
	}
	n := res.RowsAffected()
	if n == 0 {
		return Project{}, pgx.ErrNoRows
	}
	return project, nil
}

func (s *PostgresStore) DeleteProject(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("DeleteProject: missing project id")
		return errors.New("missing project id")
	}
	res, err := s.DB.Exec(ctx, `DELETE FROM projects WHERE id=$1`, id)
	if err != nil {
		logger.LogError("DeleteProject: failed", logger.ErrorField(err), logger.Any("id", id))
		return wrapDBErr("delete_project", err)
	}
	n := res.RowsAffected()
	if n == 0 {
		logger.LogError("DeleteProject: no rows affected", logger.Any("id", id))
		return pgx.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) GetProject(ctx context.Context, id string) (Project, error) {
	var p Project
	row := s.DB.QueryRow(ctx, `SELECT id, org_id, name, description, status, created_at, updated_at FROM projects WHERE id=$1`, id)
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		logger.LogError("GetProject: failed", logger.ErrorField(err), logger.Any("id", id))
		return Project{}, wrapDBErr("get_project", err)
	}
	return p, nil
}

func (s *PostgresStore) ListProjects(ctx context.Context, orgID string, page, pageSize int) ([]Project, error) {
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, `SELECT id, org_id, name, description, status, created_at, updated_at FROM projects WHERE org_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, orgID, pageSize, offset)
	if err != nil {
		logger.LogError("ListProjects: failed", logger.ErrorField(err), logger.Any("org_id", orgID))
		return nil, wrapDBErr("list_projects", err)
	}
	defer rows.Close()
	var projects []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			logger.LogError("ListProjects: scan error", logger.ErrorField(err), logger.Any("org_id", orgID))
			return nil, wrapDBErr("list_projects_scan", err)
		}
		projects = append(projects, p)
	}
	return projects, nil
}

// --- ProjectSettingsService ---
func (s *PostgresStore) GetSettings(ctx context.Context, projectID string) (map[string]interface{}, error) {
	if projectID == "" {
		logger.LogError("project id required")
		return nil, errors.New("project id required")
	}
	key := "project_settings_" + projectID
	cfg, err := s.ServerConfigService.Get(ctx, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || err.Error() == "config not found" {
			return map[string]interface{}{}, nil
		}
		logger.LogError("failed to get project settings", logger.ErrorField(err), logger.String("project_id", projectID))
		return nil, err
	}
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Value), &settings); err != nil {
		logger.LogError("invalid project settings json", logger.ErrorField(err), logger.String("project_id", projectID))
		return nil, errors.New("invalid project settings json")
	}
	return settings, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, projectID string, settings map[string]interface{}) error {
	if projectID == "" {
		logger.LogError("project id required")
		return errors.New("project id required")
	}
	key := "project_settings_" + projectID
	b, err := json.Marshal(settings)
	if err != nil {
		logger.LogError("marshal project settings failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return errors.New("invalid project settings")
	}
	_, err = s.ServerConfigService.Set(ctx, key, string(b), "system")
	if err != nil {
		logger.LogError("failed to set project settings", logger.ErrorField(err), logger.String("project_id", projectID))
		return err
	}
	return nil
}

// --- Helpers ---
func wrapDBErr(op string, err error) error {
	return &DBError{Op: op, Err: err}
}

func (e *DBError) Error() string {
	return "db error: " + e.Op + ": " + e.Err.Error()
}

func generateUUID() string {
	return uuid.NewString()
}
