package account

import (
	"context"
	"errors"


	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type BillingAccountType string

const (
	AccountTypeProject      BillingAccountType = "project"
	AccountTypeUser         BillingAccountType = "user"
	AccountTypeOrganization BillingAccountType = "organization"
)

// --- Query Constants ---
const (
	insertProjectBillingAccountQuery = `INSERT INTO project_billing_accounts (id, project_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, project_id, email, status, currency, created_at, updated_at`
	insertUserBillingAccountQuery    = `INSERT INTO user_billing_accounts (id, user_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, user_id, email, status, currency, created_at, updated_at`
	insertOrgBillingAccountQuery     = `INSERT INTO organization_billing_accounts (id, org_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, org_id, email, status, currency, created_at, updated_at`

	selectProjectBillingAccountQuery = `SELECT id, project_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE id = $1`
	selectUserBillingAccountQuery    = `SELECT id, user_id, email, status, currency, created_at, updated_at FROM user_billing_accounts WHERE id = $1`
	selectOrgBillingAccountQuery     = `SELECT id, org_id, email, status, currency, created_at, updated_at FROM organization_billing_accounts WHERE id = $1`

	updateProjectBillingAccountQuery = `UPDATE project_billing_accounts SET project_id = $2, email = $3, status = $4, currency = $5, updated_at = $6 WHERE id = $1 RETURNING id, project_id, email, status, currency, created_at, updated_at`
	updateUserBillingAccountQuery    = `UPDATE user_billing_accounts SET user_id = $2, email = $3, status = $4, currency = $5, updated_at = $6 WHERE id = $1 RETURNING id, user_id, email, status, currency, created_at, updated_at`
	updateOrgBillingAccountQuery     = `UPDATE organization_billing_accounts SET org_id = $2, email = $3, status = $4, currency = $5, updated_at = $6 WHERE id = $1 RETURNING id, org_id, email, status, currency, created_at, updated_at`

	listProjectBillingAccountsQuery = `SELECT id, project_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	listUserBillingAccountsQuery    = `SELECT id, user_id, email, status, currency, created_at, updated_at FROM user_billing_accounts WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	listOrgBillingAccountsQuery     = `SELECT id, org_id, email, status, currency, created_at, updated_at FROM organization_billing_accounts WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	performProjectBillingAccountActionQuery = `UPDATE project_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, project_id, email, status, currency, created_at, updated_at`
	performUserBillingAccountActionQuery    = `UPDATE user_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, user_id, email, status, currency, created_at, updated_at`
	performOrgBillingAccountActionQuery     = `UPDATE organization_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, org_id, email, status, currency, created_at, updated_at`

	deleteProjectBillingAccountQuery = `DELETE FROM project_billing_accounts WHERE id = $1`
	deleteUserBillingAccountQuery    = `DELETE FROM user_billing_accounts WHERE id = $1`
	deleteOrgBillingAccountQuery     = `DELETE FROM organization_billing_accounts WHERE id = $1`
)


// --- Create ---
func (s *PostgresStore) CreateBillingAccount(ctx context.Context, accountType BillingAccountType, a interface{}) (interface{}, error) {
	var q string
	var args []interface{}
	switch accountType {
	case AccountTypeProject:
		acct := a.(ProjectBillingAccount)
		q = insertProjectBillingAccountQuery
		args = []interface{}{acct.ID, acct.ProjectID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
	case AccountTypeUser:
		acct := a.(UserBillingAccount)
		q = insertUserBillingAccountQuery
		args = []interface{}{acct.ID, acct.UserID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
	case AccountTypeOrganization:
		acct := a.(OrganizationBillingAccount)
		q = insertOrgBillingAccountQuery
		args = []interface{}{acct.ID, acct.OrgID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
	default:
		return nil, errors.New("unsupported account type")
	}
	var scanArgs []interface{}
	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs = []interface{}{&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs = []interface{}{&out.ID, &out.UserID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs = []interface{}{&out.ID, &out.OrgID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("unexpected error")
}

// --- Get ---
func (s *PostgresStore) GetBillingAccount(ctx context.Context, accountType BillingAccountType, id string) (interface{}, error) {
	var q string
	switch accountType {
	case AccountTypeProject:
		q = selectProjectBillingAccountQuery
	case AccountTypeUser:
		q = selectUserBillingAccountQuery
	case AccountTypeOrganization:
		q = selectOrgBillingAccountQuery
	default:
		logger.LogError("GetBillingAccount: invalid account type", logger.String("type", string(accountType)))
		return nil, errors.New("unsupported account type")
	}
	var scanArgs []interface{}
	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs = []interface{}{&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, id)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs = []interface{}{&out.ID, &out.UserID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, id)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs = []interface{}{&out.ID, &out.OrgID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, id)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("unexpected error")
}

// --- Update ---
func (s *PostgresStore) UpdateBillingAccount(ctx context.Context, accountType BillingAccountType, a interface{}) (interface{}, error) {
	var q string
	var args []interface{}
	switch accountType {
	case AccountTypeProject:
		acct := a.(ProjectBillingAccount)
		q = updateProjectBillingAccountQuery
		args = []interface{}{acct.ID, acct.ProjectID, acct.Email, acct.Status, acct.Currency, acct.UpdatedAt}
	case AccountTypeUser:
		acct := a.(UserBillingAccount)
		q = updateUserBillingAccountQuery
		args = []interface{}{acct.ID, acct.UserID, acct.Email, acct.Status, acct.Currency, acct.UpdatedAt}
	case AccountTypeOrganization:
		acct := a.(OrganizationBillingAccount)
		q = updateOrgBillingAccountQuery
		args = []interface{}{acct.ID, acct.OrgID, acct.Email, acct.Status, acct.Currency, acct.UpdatedAt}
	default:
		return nil, errors.New("unsupported account type")
	}
	var scanArgs []interface{}
	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs = []interface{}{&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs = []interface{}{&out.ID, &out.UserID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs = []interface{}{&out.ID, &out.OrgID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("unexpected error")
}

// --- List ---
func (s *PostgresStore) ListBillingAccounts(ctx context.Context, accountType BillingAccountType, ownerID string, page, pageSize int) (interface{}, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	var q string
	var args []interface{}
	switch accountType {
	case AccountTypeProject:
		q = listProjectBillingAccountsQuery
		args = []interface{}{ownerID, pageSize, (page - 1) * pageSize}
	case AccountTypeUser:
		q = listUserBillingAccountsQuery
		args = []interface{}{ownerID, pageSize, (page - 1) * pageSize}
	case AccountTypeOrganization:
		q = listOrgBillingAccountsQuery
		args = []interface{}{ownerID, pageSize, (page - 1) * pageSize}
	default:
		logger.LogError("ListBillingAccounts: invalid account type", logger.String("type", string(accountType)))
		return nil, errors.New("unsupported account type")
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListBillingAccounts query failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return nil, err
	}
	defer rows.Close()
	switch accountType {
	case AccountTypeProject:
		var out []ProjectBillingAccount
		for rows.Next() {
			var a ProjectBillingAccount
			if err := rows.Scan(&a.ID, &a.ProjectID, &a.Email, &a.Status, &a.Currency, &a.CreatedAt, &a.UpdatedAt); err != nil {
				logger.LogError("ListBillingAccounts scan failed", logger.ErrorField(err))
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	case AccountTypeUser:
		var out []UserBillingAccount
		for rows.Next() {
			var a UserBillingAccount
			if err := rows.Scan(&a.ID, &a.UserID, &a.Email, &a.Status, &a.Currency, &a.CreatedAt, &a.UpdatedAt); err != nil {
				logger.LogError("ListBillingAccounts scan failed", logger.ErrorField(err))
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	case AccountTypeOrganization:
		var out []OrganizationBillingAccount
		for rows.Next() {
			var a OrganizationBillingAccount
			if err := rows.Scan(&a.ID, &a.OrgID, &a.Email, &a.Status, &a.Currency, &a.CreatedAt, &a.UpdatedAt); err != nil {
				logger.LogError("ListBillingAccounts scan failed", logger.ErrorField(err))
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	}
	return nil, errors.New("unexpected error")
}

// --- Perform Action ---
func (s *PostgresStore) PerformBillingAccountAction(ctx context.Context, accountType BillingAccountType, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		logger.LogError("PerformBillingAccountAction: invalid input", logger.String("account_id", accountID), logger.String("action", action))
		return nil, errors.New("account_id/action must not be empty")
	}
	var q string
	var scanArgs []interface{}
	var status string
	switch action {
	case "suspend":
		status = "suspended"
	case "activate":
		status = "active"
	case "close":
		status = "closed"
	default:
		logger.LogError("PerformBillingAccountAction: invalid action", logger.String("action", action))
		return nil, errors.New("unsupported account action")
	}
	switch accountType {
	case AccountTypeProject:
		q = performProjectBillingAccountActionQuery
		var out ProjectBillingAccount
		scanArgs = []interface{}{&out.ID, &out.ProjectID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": out,
			"action":  action,
			"status":  status,
		}, nil
	case AccountTypeUser:
		q = performUserBillingAccountActionQuery
		var out UserBillingAccount
		scanArgs = []interface{}{&out.ID, &out.UserID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": out,
			"action":  action,
			"status":  status,
		}, nil
	case AccountTypeOrganization:
		q = performOrgBillingAccountActionQuery
		var out OrganizationBillingAccount
		scanArgs = []interface{}{&out.ID, &out.OrgID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": out,
			"action":  action,
			"status":  status,
		}, nil
	default:
		logger.LogError("PerformBillingAccountAction: invalid account type", logger.String("type", string(accountType)))
		return nil, errors.New("unsupported account type")
	}
}

// --- Delete ---
func (s *PostgresStore) DeleteBillingAccount(ctx context.Context, accountType BillingAccountType, id string) error {
	var q string
	switch accountType {
	case AccountTypeProject:
		q = deleteProjectBillingAccountQuery
	case AccountTypeUser:
		q = deleteUserBillingAccountQuery
	case AccountTypeOrganization:
		q = deleteOrgBillingAccountQuery
	default:
		logger.LogError("DeleteBillingAccount: invalid account type", logger.String("type", string(accountType)))
		return errors.New("unsupported account type")
	}
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}
