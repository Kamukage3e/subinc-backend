package project_management

import (
	"context"
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
	_, err := s.db.Exec(ctx, `INSERT INTO projects (id, org_id, name, description, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		project.ID, project.OrgID, project.Name, project.Description, project.Status, project.CreatedAt, project.UpdatedAt)
	if err != nil {
		logger.LogError("CreateProject: failed", logger.ErrorField(err), logger.Any("project", project))
		return Project{}, wrapDBErr("create_project", err)
	}
	return project, nil
}

func (s *PostgresStore) UpdateProject(ctx context.Context, project Project) (Project, error) {
	project.UpdatedAt = time.Now()
	res, err := s.db.Exec(ctx, `UPDATE projects SET name=$1, description=$2, status=$3, updated_at=$4 WHERE id=$5`,
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
	res, err := s.db.Exec(ctx, `DELETE FROM projects WHERE id=$1`, id)
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
	row := s.db.QueryRow(ctx, `SELECT id, org_id, name, description, status, created_at, updated_at FROM projects WHERE id=$1`, id)
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Description, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		logger.LogError("GetProject: failed", logger.ErrorField(err), logger.Any("id", id))
		return Project{}, wrapDBErr("get_project", err)
	}
	return p, nil
}

func (s *PostgresStore) ListProjects(ctx context.Context, orgID string, page, pageSize int) ([]Project, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, `SELECT id, org_id, name, description, status, created_at, updated_at FROM projects WHERE org_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, orgID, pageSize, offset)
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

// --- ProjectInviteService ---
func (s *PostgresStore) CreateInvite(ctx context.Context, invite ProjectInvite) (ProjectInvite, error) {
	if invite.ID == "" {
		invite.ID = generateUUID()
	}

	invite.CreatedAt = time.Now()
	invite.ExpiresAt = invite.CreatedAt.Add(7 * 24 * time.Hour)
	_, err := s.db.Exec(ctx, `INSERT INTO project_invites (id, project_id, email, role, status, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		invite.ID, invite.ProjectID, invite.Email, invite.Role, invite.Status, invite.ExpiresAt, invite.CreatedAt)
	if err != nil {
		logger.LogError("CreateInvite: failed", logger.ErrorField(err), logger.Any("invite", invite))
		return ProjectInvite{}, wrapDBErr("create_invite", err)
	}
	return invite, nil
}

func (s *PostgresStore) AcceptInvite(ctx context.Context, token string) error {
	res, err := s.db.Exec(ctx, `UPDATE project_invites SET status='accepted' WHERE token=$1 AND status='pending'`, token)
	if err != nil {
		logger.LogError("AcceptInvite: failed", logger.ErrorField(err), logger.Any("token", token))
		return wrapDBErr("accept_invite", err)
	}
	n := res.RowsAffected()
	if n == 0 {
		logger.LogError("AcceptInvite: no rows affected", logger.Any("token", token))
		return pgx.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) RevokeInvite(ctx context.Context, id string) error {
	res, err := s.db.Exec(ctx, `UPDATE project_invites SET status='revoked' WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		logger.LogError("RevokeInvite: failed", logger.ErrorField(err), logger.Any("id", id))
		return wrapDBErr("revoke_invite", err)
	}
	n := res.RowsAffected()
	if n == 0 {
		logger.LogError("RevokeInvite: no rows affected", logger.Any("id", id))
		return pgx.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) ListInvites(ctx context.Context, projectID string, page, pageSize int) ([]ProjectInvite, error) {
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, `SELECT id, project_id, email, role, status, token, expires_at, created_at FROM project_invites WHERE project_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, projectID, pageSize, offset)
	if err != nil {
		logger.LogError("ListInvites: failed", logger.ErrorField(err), logger.Any("project_id", projectID))
		return nil, wrapDBErr("list_invites", err)
	}
	defer rows.Close()
	var invites []ProjectInvite
	for rows.Next() {
		var i ProjectInvite
		if err := rows.Scan(&i.ID, &i.ProjectID, &i.Email, &i.Role, &i.Status, &i.Token, &i.ExpiresAt, &i.CreatedAt); err != nil {
			logger.LogError("ListInvites: scan error", logger.ErrorField(err), logger.Any("project_id", projectID))
			return nil, wrapDBErr("list_invites_scan", err)
		}
		invites = append(invites, i)
	}
	return invites, nil
}

// --- ProjectSettingsService ---
func (s *PostgresStore) GetSettings(ctx context.Context, projectID string) (ProjectSettings, error) {
	var ps ProjectSettings
	row := s.db.QueryRow(ctx, `SELECT project_id, settings, updated_at FROM project_settings WHERE project_id=$1`, projectID)
	err := row.Scan(&ps.ProjectID, &ps.Settings, &ps.UpdatedAt)
	if err != nil {
		logger.LogError("GetSettings: failed", logger.ErrorField(err), logger.Any("project_id", projectID))
		return ProjectSettings{}, wrapDBErr("get_settings", err)
	}
	return ps, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, projectID, settings string) error {
	_, err := s.db.Exec(ctx, `UPDATE project_settings SET settings=$1, updated_at=$2 WHERE project_id=$3`, settings, time.Now(), projectID)
	if err != nil {
		logger.LogError("UpdateSettings: failed", logger.ErrorField(err), logger.Any("project_id", projectID))
		return wrapDBErr("update_settings", err)
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
