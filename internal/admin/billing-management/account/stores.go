package account

import (
	"context"
	"errors"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// CreateProjectBillingAccount inserts a new project billing account into the DB
func (s *PostgresStore) CreateProjectBillingAccount(ctx context.Context, a ProjectBillingAccount) (ProjectBillingAccount, error) {
	const q = `INSERT INTO project_billing_accounts (id, project_id, email, status, currency, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, project_id, email, status, currency, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, a.ID, a.ProjectID, a.Email, a.Status, a.Currency, a.CreatedAt, a.UpdatedAt)
	var out ProjectBillingAccount
	if err := row.Scan(&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreateProjectBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return ProjectBillingAccount{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetProjectBillingAccount(ctx context.Context, id string) (ProjectBillingAccount, error) {
	const q = `SELECT id, project_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out ProjectBillingAccount
	if err := row.Scan(&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("GetProjectBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
		return ProjectBillingAccount{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateProjectBillingAccount(ctx context.Context, a ProjectBillingAccount) (ProjectBillingAccount, error) {
	const q = `UPDATE project_billing_accounts SET project_id = $2, email = $3, status = $4, currency = $5, updated_at = $6 WHERE id = $1 RETURNING id, project_id, email, status, currency, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, a.ID, a.ProjectID, a.Email, a.Status, a.Currency, a.UpdatedAt)
	var out ProjectBillingAccount
	if err := row.Scan(&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateProjectBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return ProjectBillingAccount{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListProjectBillingAccounts(ctx context.Context, projectID string, page, pageSize int) ([]ProjectBillingAccount, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, project_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, q, projectID, pageSize, offset)
	if err != nil {
		logger.LogError("ListProjectBillingAccounts query failed", logger.ErrorField(err), logger.String("project_id", projectID))
		return nil, err
	}
	defer rows.Close()
	var out []ProjectBillingAccount
	for rows.Next() {
		var a ProjectBillingAccount
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Email, &a.Status, &a.Currency, &a.CreatedAt, &a.UpdatedAt); err != nil {
			logger.LogError("ListProjectBillingAccounts scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (s *PostgresStore) PerformProjectBillingAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		logger.LogError("PerformProjectBillingAccountAction: invalid input", logger.String("account_id", accountID), logger.String("action", action))
		return nil, errors.New("account_id/action must not be empty")
	}
	var status string
	switch action {
	case "suspend":
		status = "suspended"
	case "activate":
		status = "active"
	case "close":
		status = "closed"
	default:
		logger.LogError("PerformProjectBillingAccountAction: invalid action", logger.String("action", action))
		return nil, errors.New("unsupported account action")
	}
	const q = `UPDATE project_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, project_id, email, status, currency, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, status, accountID)
	var out ProjectBillingAccount
	if err := row.Scan(&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("PerformProjectBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
		return nil, err
	}
	return map[string]interface{}{
		"account": out,
		"action":  action,
		"status":  status,
	}, nil
}

func (s *PostgresStore) DeleteProjectBillingAccount(ctx context.Context, id string) error {
	const q = `DELETE FROM project_billing_accounts WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteProjectBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}
