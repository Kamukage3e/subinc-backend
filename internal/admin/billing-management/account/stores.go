package account

import (
	"context"
	"errors"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	
)

// CreateAccount inserts a new account into the DB
func (s *PostgresStore) CreateAccount(ctx context.Context, a Account) (Account, error) {
	const q = `INSERT INTO accounts (id, tenant_id, email, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, a.ID, a.TenantID, a.Email, a.Status, a.CreatedAt, a.UpdatedAt)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreateAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return Account{}, err
	}
	return out, nil
}

// GetAccount fetches an account by ID
func (s *PostgresStore) GetAccount(ctx context.Context, id string) (Account, error) {
	const q = `SELECT id, tenant_id, email, status, created_at, updated_at FROM accounts WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			logger.LogWarn("GetAccount: not found", logger.String("id", id))
			return Account{}, errors.New("no rows")
		}
		logger.LogError("GetAccount failed", logger.ErrorField(err), logger.String("id", id))
		return Account{}, err
	}
	return out, nil
}

// UpdateAccount updates an account in the DB
func (s *PostgresStore) UpdateAccount(ctx context.Context, a Account) (Account, error) {
	const q = `UPDATE accounts SET tenant_id = $2, email = $3, status = $4, updated_at = $5 WHERE id = $1 RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, a.ID, a.TenantID, a.Email, a.Status, a.UpdatedAt)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return Account{}, err
	}
	return out, nil
}

// ListAccounts returns a paginated list of accounts for a tenant
func (s *PostgresStore) ListAccounts(ctx context.Context, tenantID string, page, pageSize int) ([]Account, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, email, status, created_at, updated_at FROM accounts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		logger.LogError("ListAccounts query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Email, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			logger.LogError("ListAccounts scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// --- AccountAction ---
func (s *PostgresStore) PerformAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		logger.LogError("PerformAccountAction: invalid input", logger.String("account_id", accountID), logger.String("action", action))
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
		logger.LogError("PerformAccountAction: invalid action", logger.String("action", action))
		return nil, errors.New("unsupported account action")
	}
	const q = `UPDATE accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, status, accountID)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("PerformAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
		return nil, err
	}
	return map[string]interface{}{
		"account": out,
		"action":  action,
		"status":  status,
	}, nil
}