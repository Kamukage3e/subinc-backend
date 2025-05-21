package account

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
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
	insertProjectBillingAccountQuery = `INSERT INTO project_billing_accounts (id, project_id, tenant_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, project_id, tenant_id, email, status, currency, created_at, updated_at`
	insertUserBillingAccountQuery    = `INSERT INTO user_billing_accounts (id, user_id, tenant_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, user_id, tenant_id, email, status, currency, created_at, updated_at`
	insertOrgBillingAccountQuery     = `INSERT INTO organization_billing_accounts (id, org_id, tenant_id, email, status, currency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, org_id, tenant_id, email, status, currency, created_at, updated_at`

	selectProjectBillingAccountQuery = `SELECT id, project_id, tenant_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE id = $1`
	selectUserBillingAccountQuery    = `SELECT id, user_id, tenant_id, email, status, currency, created_at, updated_at FROM user_billing_accounts WHERE id = $1`
	selectOrgBillingAccountQuery     = `SELECT id, org_id, tenant_id, email, status, currency, created_at, updated_at FROM organization_billing_accounts WHERE id = $1`

	updateProjectBillingAccountQuery = `UPDATE project_billing_accounts SET project_id = $2, email = $3, status = $4, currency = $5, updated_at = NOW() WHERE id = $1 RETURNING id, project_id, tenant_id, email, status, currency, created_at, updated_at`
	updateUserBillingAccountQuery    = `UPDATE user_billing_accounts SET user_id = $2, email = $3, status = $4, currency = $5, updated_at = NOW() WHERE id = $1 RETURNING id, user_id, tenant_id, email, status, currency, created_at, updated_at`
	updateOrgBillingAccountQuery     = `UPDATE organization_billing_accounts SET org_id = $2, email = $3, status = $4, currency = $5, updated_at = NOW() WHERE id = $1 RETURNING id, org_id, tenant_id, email, status, currency, created_at, updated_at`

	listProjectBillingAccountsQuery = `SELECT id, project_id, tenant_id, email, status, currency, created_at, updated_at FROM project_billing_accounts WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	listUserBillingAccountsQuery    = `SELECT id, user_id, tenant_id, email, status, currency, created_at, updated_at FROM user_billing_accounts WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	listOrgBillingAccountsQuery     = `SELECT id, org_id, tenant_id, email, status, currency, created_at, updated_at FROM organization_billing_accounts WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	performProjectBillingAccountActionQuery = `UPDATE project_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, project_id, tenant_id, email, status, currency, created_at, updated_at`
	performUserBillingAccountActionQuery    = `UPDATE user_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, user_id, tenant_id, email, status, currency, created_at, updated_at`
	performOrgBillingAccountActionQuery     = `UPDATE organization_billing_accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, org_id, tenant_id, email, status, currency, created_at, updated_at`

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
		acct, ok := a.(*ProjectBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("CreateBillingAccount: invalid type assertion", logger.String("expected", "*ProjectBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = insertProjectBillingAccountQuery
		args = []interface{}{acct.ID, acct.ProjectID, acct.TenantID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
		if acct.ProjectID == "" || acct.TenantID == "" {
			err := errors.New("project_id and tenant_id are required")
			logger.LogError("CreateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	case AccountTypeUser:
		acct, ok := a.(*UserBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("CreateBillingAccount: invalid type assertion", logger.String("expected", "*UserBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = insertUserBillingAccountQuery
		args = []interface{}{acct.ID, acct.UserID, acct.TenantID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
		if acct.UserID == "" || acct.TenantID == "" {
			err := errors.New("user_id and tenant_id are required")
			logger.LogError("CreateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	case AccountTypeOrganization:
		acct, ok := a.(*OrganizationBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("CreateBillingAccount: invalid type assertion", logger.String("expected", "*OrganizationBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = insertOrgBillingAccountQuery
		args = []interface{}{acct.ID, acct.OrgID, acct.TenantID, acct.Email, acct.Status, acct.Currency, acct.CreatedAt, acct.UpdatedAt}
		if acct.OrgID == "" || acct.TenantID == "" {
			err := errors.New("org_id and tenant_id are required")
			logger.LogError("CreateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	default:
		err := errors.New("unsupported account type")
		logger.LogError("CreateBillingAccount: unsupported account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return nil, err
	}

	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs := []interface{}{&out.ID, &out.ProjectID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeProject && err.Error() == "ERROR: relation \"project_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("CreateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("project billing accounts table does not exist, please run migrations")
			}
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs := []interface{}{&out.ID, &out.UserID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeUser && err.Error() == "ERROR: relation \"user_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("CreateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("user billing accounts table does not exist, please run migrations")
			}
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs := []interface{}{&out.ID, &out.OrgID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeOrganization && err.Error() == "ERROR: relation \"organization_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("CreateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("organization billing accounts table does not exist, please run migrations")
			}
			logger.LogError("CreateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	}

	err := errors.New("unexpected error")
	logger.LogError("CreateBillingAccount: unexpected error", logger.ErrorField(err))
	return nil, err
}

// --- Get ---
func (s *PostgresStore) GetBillingAccount(ctx context.Context, accountType BillingAccountType, id string) (interface{}, error) {
	if id == "" {
		err := errors.New("account id is required")
		logger.LogError("GetBillingAccount: id required", logger.String("id", id), logger.ErrorField(err))
		return nil, err
	}

	// Get tenant ID from context if available for tenant isolation
	tenantID := getTenantIDFromContext(ctx)

	var q string
	var args []interface{}

	// Add tenant filtering to queries if tenant ID is available
	switch accountType {
	case AccountTypeProject:
		if tenantID != "" {
			q = `SELECT id, project_id, tenant_id, email, status, currency, created_at, updated_at 
				FROM project_billing_accounts 
				WHERE id = $1 AND tenant_id = $2`
			args = []interface{}{id, tenantID}
		} else {
			q = selectProjectBillingAccountQuery
			args = []interface{}{id}
		}
	case AccountTypeUser:
		if tenantID != "" {
			q = `SELECT id, user_id, tenant_id, email, status, currency, created_at, updated_at 
				FROM user_billing_accounts 
				WHERE id = $1 AND tenant_id = $2`
			args = []interface{}{id, tenantID}
		} else {
			q = selectUserBillingAccountQuery
			args = []interface{}{id}
		}
	case AccountTypeOrganization:
		if tenantID != "" {
			q = `SELECT id, org_id, tenant_id, email, status, currency, created_at, updated_at 
				FROM organization_billing_accounts 
				WHERE id = $1 AND tenant_id = $2`
			args = []interface{}{id, tenantID}
		} else {
			q = selectOrgBillingAccountQuery
			args = []interface{}{id}
		}
	default:
		err := errors.New("unsupported account type")
		logger.LogError("GetBillingAccount: invalid account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return nil, err
	}

	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs := []interface{}{&out.ID, &out.ProjectID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return &out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs := []interface{}{&out.ID, &out.UserID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return &out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs := []interface{}{&out.ID, &out.OrgID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("GetBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
			return nil, err
		}
		return &out, nil
	}

	err := errors.New("unexpected error")
	logger.LogError("GetBillingAccount: unexpected error", logger.ErrorField(err))
	return nil, err
}

// --- Update ---
func (s *PostgresStore) UpdateBillingAccount(ctx context.Context, accountType BillingAccountType, a interface{}) (interface{}, error) {
	var q string
	var args []interface{}

	switch accountType {
	case AccountTypeProject:
		acct, ok := a.(*ProjectBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("UpdateBillingAccount: invalid type assertion", logger.String("expected", "*ProjectBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = updateProjectBillingAccountQuery
		args = []interface{}{acct.ID, acct.ProjectID, acct.Email, acct.Status, acct.Currency}
		if acct.ID == "" || acct.ProjectID == "" {
			err := errors.New("id and project_id are required")
			logger.LogError("UpdateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	case AccountTypeUser:
		acct, ok := a.(*UserBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("UpdateBillingAccount: invalid type assertion", logger.String("expected", "*UserBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = updateUserBillingAccountQuery
		args = []interface{}{acct.ID, acct.UserID, acct.Email, acct.Status, acct.Currency}
		if acct.ID == "" || acct.UserID == "" {
			err := errors.New("id and user_id are required")
			logger.LogError("UpdateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	case AccountTypeOrganization:
		acct, ok := a.(*OrganizationBillingAccount)
		if !ok {
			err := errors.New("invalid account data format")
			logger.LogError("UpdateBillingAccount: invalid type assertion", logger.String("expected", "*OrganizationBillingAccount"), logger.Any("received", a), logger.ErrorField(err))
			return nil, err
		}
		q = updateOrgBillingAccountQuery
		args = []interface{}{acct.ID, acct.OrgID, acct.Email, acct.Status, acct.Currency}
		if acct.ID == "" || acct.OrgID == "" {
			err := errors.New("id and org_id are required")
			logger.LogError("UpdateBillingAccount: missing required field", logger.Any("account", acct), logger.ErrorField(err))
			return nil, err
		}
	default:
		err := errors.New("unsupported account type")
		logger.LogError("UpdateBillingAccount: unsupported account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return nil, err
	}

	switch accountType {
	case AccountTypeProject:
		var out ProjectBillingAccount
		scanArgs := []interface{}{&out.ID, &out.ProjectID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeProject && err.Error() == "ERROR: relation \"project_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("UpdateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("project billing accounts table does not exist, please run migrations")
			}
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	case AccountTypeUser:
		var out UserBillingAccount
		scanArgs := []interface{}{&out.ID, &out.UserID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeUser && err.Error() == "ERROR: relation \"user_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("UpdateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("user billing accounts table does not exist, please run migrations")
			}
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	case AccountTypeOrganization:
		var out OrganizationBillingAccount
		scanArgs := []interface{}{&out.ID, &out.OrgID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, args...)
		if err := row.Scan(scanArgs...); err != nil {
			if accountType == AccountTypeOrganization && err.Error() == "ERROR: relation \"organization_billing_accounts\" does not exist (SQLSTATE 42P01)" {
				logger.LogError("UpdateBillingAccount: table does not exist", logger.ErrorField(err))
				return nil, errors.New("organization billing accounts table does not exist, please run migrations")
			}
			logger.LogError("UpdateBillingAccount failed", logger.ErrorField(err), logger.Any("account", a))
			return nil, err
		}
		return &out, nil
	}

	err := errors.New("unexpected error")
	logger.LogError("UpdateBillingAccount: unexpected error", logger.ErrorField(err))
	return nil, err
}

// --- List ---
func (s *PostgresStore) ListBillingAccounts(ctx context.Context, accountType BillingAccountType, ownerID string, page, pageSize int) (interface{}, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	offset := (page - 1) * pageSize

	// Get tenant ID from context if available for tenant isolation
	tenantID := getTenantIDFromContext(ctx)

	var q string
	var args []interface{}
	var err error

	// Add tenant filtering to queries if tenant ID is available
	switch accountType {
	case AccountTypeProject:
		if tenantID != "" {
			if ownerID != "" {
				q = `SELECT id, project_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM project_billing_accounts 
					WHERE project_id = $1 AND tenant_id = $2
					ORDER BY created_at DESC LIMIT $3 OFFSET $4`
				args = []interface{}{ownerID, tenantID, pageSize, offset}
			} else {
				q = `SELECT id, project_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM project_billing_accounts 
					WHERE tenant_id = $1
					ORDER BY created_at DESC LIMIT $2 OFFSET $3`
				args = []interface{}{tenantID, pageSize, offset}
			}
		} else {
			if ownerID == "" {
				err = errors.New("project_id or tenant_id required")
				logger.LogError("ListBillingAccounts: missing filter", logger.ErrorField(err))
				return nil, err
			}
			q = listProjectBillingAccountsQuery
			args = []interface{}{ownerID, pageSize, offset}
		}
	case AccountTypeUser:
		if tenantID != "" {
			if ownerID != "" {
				q = `SELECT id, user_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM user_billing_accounts 
					WHERE user_id = $1 AND tenant_id = $2
					ORDER BY created_at DESC LIMIT $3 OFFSET $4`
				args = []interface{}{ownerID, tenantID, pageSize, offset}
			} else {
				q = `SELECT id, user_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM user_billing_accounts 
					WHERE tenant_id = $1
					ORDER BY created_at DESC LIMIT $2 OFFSET $3`
				args = []interface{}{tenantID, pageSize, offset}
			}
		} else {
			if ownerID == "" {
				err = errors.New("user_id or tenant_id required")
				logger.LogError("ListBillingAccounts: missing filter", logger.ErrorField(err))
				return nil, err
			}
			q = listUserBillingAccountsQuery
			args = []interface{}{ownerID, pageSize, offset}
		}
	case AccountTypeOrganization:
		if tenantID != "" {
			if ownerID != "" {
				q = `SELECT id, org_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM organization_billing_accounts 
					WHERE org_id = $1 AND tenant_id = $2
					ORDER BY created_at DESC LIMIT $3 OFFSET $4`
				args = []interface{}{ownerID, tenantID, pageSize, offset}
			} else {
				q = `SELECT id, org_id, tenant_id, email, status, currency, created_at, updated_at 
					FROM organization_billing_accounts 
					WHERE tenant_id = $1
					ORDER BY created_at DESC LIMIT $2 OFFSET $3`
				args = []interface{}{tenantID, pageSize, offset}
			}
		} else {
			if ownerID == "" {
				err = errors.New("org_id or tenant_id required")
				logger.LogError("ListBillingAccounts: missing filter", logger.ErrorField(err))
				return nil, err
			}
			q = listOrgBillingAccountsQuery
			args = []interface{}{ownerID, pageSize, offset}
		}
	default:
		err = errors.New("unsupported account type")
		logger.LogError("ListBillingAccounts: unsupported account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return nil, err
	}

	var rows pgx.Rows
	rows, err = s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListBillingAccounts: query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	switch accountType {
	case AccountTypeProject:
		var accounts []*ProjectBillingAccount
		for rows.Next() {
			var account ProjectBillingAccount
			err = rows.Scan(&account.ID, &account.ProjectID, &account.TenantID, &account.Email, &account.Status, &account.Currency, &account.CreatedAt, &account.UpdatedAt)
			if err != nil {
				logger.LogError("ListBillingAccounts: scan failed", logger.ErrorField(err))
				return nil, err
			}
			accounts = append(accounts, &account)
		}
		if rows.Err() != nil {
			logger.LogError("ListBillingAccounts: iteration error", logger.ErrorField(rows.Err()))
			return nil, rows.Err()
		}
		return accounts, nil
	case AccountTypeUser:
		var accounts []*UserBillingAccount
		for rows.Next() {
			var account UserBillingAccount
			err = rows.Scan(&account.ID, &account.UserID, &account.TenantID, &account.Email, &account.Status, &account.Currency, &account.CreatedAt, &account.UpdatedAt)
			if err != nil {
				logger.LogError("ListBillingAccounts: scan failed", logger.ErrorField(err))
				return nil, err
			}
			accounts = append(accounts, &account)
		}
		if rows.Err() != nil {
			logger.LogError("ListBillingAccounts: iteration error", logger.ErrorField(rows.Err()))
			return nil, rows.Err()
		}
		return accounts, nil
	case AccountTypeOrganization:
		var accounts []*OrganizationBillingAccount
		for rows.Next() {
			var account OrganizationBillingAccount
			err = rows.Scan(&account.ID, &account.OrgID, &account.TenantID, &account.Email, &account.Status, &account.Currency, &account.CreatedAt, &account.UpdatedAt)
			if err != nil {
				logger.LogError("ListBillingAccounts: scan failed", logger.ErrorField(err))
				return nil, err
			}
			accounts = append(accounts, &account)
		}
		if rows.Err() != nil {
			logger.LogError("ListBillingAccounts: iteration error", logger.ErrorField(rows.Err()))
			return nil, rows.Err()
		}
		return accounts, nil
	}

	err = errors.New("unexpected error")
	logger.LogError("ListBillingAccounts: unexpected error", logger.ErrorField(err))
	return nil, err
}

// --- Perform Action ---
func (s *PostgresStore) PerformBillingAccountAction(ctx context.Context, accountType BillingAccountType, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		err := errors.New("account_id/action must not be empty")
		logger.LogError("PerformBillingAccountAction: invalid input", logger.String("account_id", accountID), logger.String("action", action), logger.ErrorField(err))
		return nil, err
	}
	var q string
	var status string
	switch action {
	case "suspend":
		status = "suspended"
	case "activate":
		status = "active"
	case "close":
		status = "closed"
	default:
		err := errors.New("unsupported account action")
		logger.LogError("PerformBillingAccountAction: invalid action", logger.String("action", action), logger.ErrorField(err))
		return nil, err
	}
	switch accountType {
	case AccountTypeProject:
		q = performProjectBillingAccountActionQuery
		var out ProjectBillingAccount
		scanArgs := []interface{}{&out.ID, &out.ProjectID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": &out,
			"action":  action,
			"status":  status,
		}, nil
	case AccountTypeUser:
		q = performUserBillingAccountActionQuery
		var out UserBillingAccount
		scanArgs := []interface{}{&out.ID, &out.UserID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": &out,
			"action":  action,
			"status":  status,
		}, nil
	case AccountTypeOrganization:
		q = performOrgBillingAccountActionQuery
		var out OrganizationBillingAccount
		scanArgs := []interface{}{&out.ID, &out.OrgID, &out.TenantID, &out.Email, &out.Status, &out.Currency, &out.CreatedAt, &out.UpdatedAt}
		row := s.DB.QueryRow(ctx, q, status, accountID)
		if err := row.Scan(scanArgs...); err != nil {
			logger.LogError("PerformBillingAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
			return nil, err
		}
		return map[string]interface{}{
			"account": &out,
			"action":  action,
			"status":  status,
		}, nil
	default:
		err := errors.New("unsupported account type")
		logger.LogError("PerformBillingAccountAction: invalid account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return nil, err
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
		err := errors.New("unsupported account type")
		logger.LogError("DeleteBillingAccount: invalid account type", logger.String("type", string(accountType)), logger.ErrorField(err))
		return err
	}
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteBillingAccount failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

// getTenantIDFromContext safely extracts the tenant ID from context if available
func getTenantIDFromContext(ctx context.Context) string {
	tenantID := ""
	// Try to get from context value (set by middleware)
	if v := ctx.Value("tenant_id"); v != nil {
		if tid, ok := v.(string); ok && tid != "" {
			tenantID = tid
		}
	}
	return tenantID
}
