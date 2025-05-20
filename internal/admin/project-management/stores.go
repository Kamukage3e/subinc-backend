package project_management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// DB store implementations for project-management admin module will go here.

// --- ProjectService ---
func (s *PostgresStore) CreateProject(ctx context.Context, project Project) (Project, error) {
	if project.ID == "" {
		project.ID = commonutil.GenerateUUID()
	}

	// If OrgID is empty, use NULL
	var orgID interface{} = nil
	if project.OrgID != "" {
		orgID = project.OrgID
	}

	// Make sure description is not empty as it's NOT NULL in the database
	if project.Description == "" {
		project.Description = "No description provided"
	}

	project.CreatedAt = time.Now()
	project.UpdatedAt = project.CreatedAt

	// Initialize tags if nil
	if project.Tags == nil {
		project.Tags = make(map[string]string)
	}

	// Convert tags to JSON
	tagsJSON, err := json.Marshal(project.Tags)
	if err != nil {
		logger.LogError("CreateProject: failed to marshal tags", logger.ErrorField(err))
		return Project{}, errors.New("invalid tags format")
	}

	_, err = s.DB.Exec(ctx,
		`INSERT INTO projects (id, org_id, name, description, status, tags, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
		project.ID, orgID, project.Name, project.Description, project.Status,
		tagsJSON, project.CreatedAt, project.UpdatedAt)

	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("project", project))
		return Project{}, commonutil.WrapDBErr("create_project", err)
	}

	return project, nil
}

func (s *PostgresStore) UpdateProject(ctx context.Context, project Project) (Project, error) {
	project.UpdatedAt = time.Now()

	// Initialize tags if nil
	if project.Tags == nil {
		project.Tags = make(map[string]string)
	}

	// Make sure description is not empty as it's NOT NULL in the database
	if project.Description == "" {
		project.Description = "No description provided"
	}

	// Convert tags to JSON and set a default if it's nil
	jsonTags := "{}"
	if project.Tags != nil {
		tagsJSON, err := json.Marshal(project.Tags)
		if err != nil {
			logger.LogError("UpdateProject: failed to marshal tags", logger.ErrorField(err))
			return Project{}, errors.New("invalid tags format")
		}
		jsonTags = string(tagsJSON)
	}

	// If OrgID is empty, use NULL
	var orgID interface{} = nil
	if project.OrgID != "" {
		orgID = project.OrgID
	}

	sql := `UPDATE projects 
		SET name=$1, description=$2, status=$3, tags=$4::jsonb, org_id=$5, updated_at=$6 
		WHERE id=$7`

	res, err := s.DB.Exec(ctx, sql,
		project.Name, project.Description, project.Status, jsonTags, orgID, project.UpdatedAt, project.ID)

	if err != nil {
		logger.LogError("UpdateProject: failed", logger.ErrorField(err), logger.Any("project", project))
		return Project{}, commonutil.WrapDBErr("update_project", err)
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
		return commonutil.WrapDBErr("delete_project", err)
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
	var tagsJSON []byte
	var orgID sql.NullString

	query := `SELECT id, org_id, name, description, status, tags, created_at, updated_at 
		FROM projects WHERE id=$1`

	row := s.DB.QueryRow(ctx, query, id)

	err := row.Scan(&p.ID, &orgID, &p.Name, &p.Description, &p.Status, &tagsJSON, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		logger.LogError("GetProject: failed", logger.ErrorField(err), logger.Any("id", id))
		return Project{}, commonutil.WrapDBErr("get_project", err)
	}

	// Set OrgID if not null
	if orgID.Valid {
		p.OrgID = orgID.String
	}

	// Parse tags from JSON
	if tagsJSON != nil {
		if err := json.Unmarshal(tagsJSON, &p.Tags); err != nil {
			logger.LogError("GetProject: failed to unmarshal tags", logger.ErrorField(err), logger.Any("id", id))
			p.Tags = make(map[string]string) // Default to empty tags on error
		}
	} else {
		p.Tags = make(map[string]string) // Default to empty tags if NULL
	}

	return p, nil
}

func (s *PostgresStore) ListProjects(ctx context.Context, orgID string, page, pageSize int) ([]Project, error) {
	offset := (page - 1) * pageSize

	var rows pgx.Rows
	var err error

	query := `SELECT id, org_id, name, description, status, tags, created_at, updated_at 
		FROM projects`

	if orgID != "" {
		// If orgID is provided, filter by it
		query += ` WHERE org_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		rows, err = s.DB.Query(ctx, query, orgID, pageSize, offset)
	} else {
		// If orgID is not provided, list all projects
		query += ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		rows, err = s.DB.Query(ctx, query, pageSize, offset)
	}

	if err != nil {
		logger.LogError("ListProjects: failed", logger.ErrorField(err), logger.Any("org_id", orgID))
		return nil, commonutil.WrapDBErr("list_projects", err)
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var p Project
		var tagsJSON []byte
		var projectOrgID sql.NullString

		if err := rows.Scan(&p.ID, &projectOrgID, &p.Name, &p.Description, &p.Status, &tagsJSON, &p.CreatedAt, &p.UpdatedAt); err != nil {
			logger.LogError("ListProjects: scan error", logger.ErrorField(err), logger.Any("org_id", orgID))
			return nil, commonutil.WrapDBErr("list_projects_scan", err)
		}

		// Set OrgID if not null
		if projectOrgID.Valid {
			p.OrgID = projectOrgID.String
		}

		// Parse tags from JSON
		if tagsJSON != nil {
			if err := json.Unmarshal(tagsJSON, &p.Tags); err != nil {
				logger.LogError("ListProjects: failed to unmarshal tags", logger.ErrorField(err))
				p.Tags = make(map[string]string) // Default to empty tags on error
			}
		} else {
			p.Tags = make(map[string]string) // Default to empty tags if NULL
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
		// Return empty settings instead of error on malformed JSON
		return map[string]interface{}{}, nil
	}
	return settings, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, projectID string, settings map[string]interface{}) (map[string]interface{}, error) {
	if projectID == "" {
		logger.LogError("project id required")
		return nil, errors.New("project id required")
	}
	key := "project_settings_" + projectID
	b, err := json.Marshal(settings)
	if err != nil {
		logger.LogError("marshal project settings failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return nil, errors.New("invalid project settings")
	}
	_, err = s.ServerConfigService.Set(ctx, key, string(b), "system")
	if err != nil {
		logger.LogError("failed to set project settings", logger.ErrorField(err), logger.String("project_id", projectID))
		return nil, err
	}
	return settings, nil
}

func NewPostgresStore(db *pgxpool.Pool, serverConfigService *server_config.Service) *PostgresStore {
	if db == nil {
		panic("PostgresStore: DB must not be nil")
	}
	if serverConfigService == nil {
		panic("PostgresStore: ServerConfigService must not be nil (required for all secrets/keys)")
	}
	return &PostgresStore{
		DB:                  db,
		ServerConfigService: serverConfigService,

	}
}
