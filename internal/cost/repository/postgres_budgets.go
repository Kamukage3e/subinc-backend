package repository

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// CreateBudget creates a budget
func (r *PostgresCostRepository) CreateBudget(ctx context.Context, budget *domain.Budget) error {
	if err := validateBudget(budget); err != nil {
		r.logger.Error("Failed to validate budget",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return err
	}

	const q = `INSERT INTO budgets (
		id, tenant_id, name, description, provider, account_id, service, amount, 
		currency, period, start_time, end_time, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
	)`

	_, err := r.db.Exec(ctx, q,
		budget.ID,
		budget.TenantID,
		budget.Name,
		budget.Description,
		budget.Provider,
		budget.AccountID,
		budget.Service,
		budget.Amount,
		budget.Currency,
		budget.Period,
		budget.StartTime,
		budget.EndTime,
		budget.CreatedAt,
		budget.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create budget",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return fmt.Errorf("failed to create budget: %w", err)
	}

	r.logger.Info("Successfully created budget",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID),
		logger.String("name", budget.Name),
		logger.Float64("amount", budget.Amount),
		logger.String("currency", budget.Currency))

	return nil
}

// UpdateBudget updates a budget
func (r *PostgresCostRepository) UpdateBudget(ctx context.Context, budget *domain.Budget) error {
	if err := validateBudget(budget); err != nil {
		r.logger.Error("Failed to validate budget for update",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return err
	}

	const q = `UPDATE budgets SET 
		name = $1, description = $2, provider = $3, account_id = $4, service = $5, 
		amount = $6, currency = $7, period = $8, start_time = $9, end_time = $10, updated_at = $11
		WHERE id = $12 AND tenant_id = $13`

	result, err := r.db.Exec(ctx, q,
		budget.Name,
		budget.Description,
		budget.Provider,
		budget.AccountID,
		budget.Service,
		budget.Amount,
		budget.Currency,
		budget.Period,
		budget.StartTime,
		budget.EndTime,
		budget.UpdatedAt,
		budget.ID,
		budget.TenantID,
	)

	if err != nil {
		r.logger.Error("Failed to update budget",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return fmt.Errorf("failed to update budget: %w", err)
	}

	// Ensure the record was actually updated
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		r.logger.Warn("No rows affected when updating budget",
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return domain.NewEntityNotFoundError("budget", budget.ID)
	}

	r.logger.Info("Successfully updated budget",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID),
		logger.Float64("amount", budget.Amount))

	return nil
}

// DeleteBudget deletes a budget
func (r *PostgresCostRepository) DeleteBudget(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("Invalid budget ID for deletion", logger.String("budget_id", id))
		return domain.ErrInvalidResource
	}

	const q = `DELETE FROM budgets WHERE id = $1`
	result, err := r.db.Exec(ctx, q, id)

	if err != nil {
		r.logger.Error("Failed to delete budget",
			logger.ErrorField(err),
			logger.String("budget_id", id))
		return fmt.Errorf("failed to delete budget: %w", err)
	}

	// Check if the budget was actually deleted
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		r.logger.Warn("No rows affected when deleting budget",
			logger.String("budget_id", id))
		return domain.NewEntityNotFoundError("budget", id)
	}

	r.logger.Info("Successfully deleted budget",
		logger.String("budget_id", id))

	return nil
}

// GetBudgetByID retrieves a budget by ID
func (r *PostgresCostRepository) GetBudgetByID(ctx context.Context, id string) (*domain.Budget, error) {
	if id == "" {
		r.logger.Error("Invalid budget ID", logger.String("budget_id", id))
		return nil, domain.ErrInvalidResource
	}

	const q = `SELECT id, tenant_id, name, description, provider, account_id, service, 
		amount, currency, period, start_time, end_time, created_at, updated_at 
		FROM budgets WHERE id = $1`

	r.logger.Debug("Retrieving budget by ID", logger.String("budget_id", id))

	row := r.db.QueryRow(ctx, q, id)
	var b domain.Budget
	err := row.Scan(
		&b.ID,
		&b.TenantID,
		&b.Name,
		&b.Description,
		&b.Provider,
		&b.AccountID,
		&b.Service,
		&b.Amount,
		&b.Currency,
		&b.Period,
		&b.StartTime,
		&b.EndTime,
		&b.CreatedAt,
		&b.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Budget not found", logger.String("budget_id", id))
			return nil, domain.NewEntityNotFoundError("budget", id)
		}

		r.logger.Error("Failed to get budget",
			logger.ErrorField(err),
			logger.String("budget_id", id))
		return nil, fmt.Errorf("failed to get budget: %w", err)
	}

	r.logger.Debug("Successfully retrieved budget",
		logger.String("budget_id", id),
		logger.String("tenant_id", b.TenantID),
		logger.String("name", b.Name))

	return &b, nil
}

// ListBudgets lists budgets
func (r *PostgresCostRepository) ListBudgets(ctx context.Context, tenantID string, provider domain.CloudProvider, active bool, page, pageSize int) ([]*domain.Budget, int, error) {
	if tenantID == "" {
		r.logger.Error("Invalid tenant ID for listing budgets")
		return nil, 0, domain.ErrInvalidTenant
	}

	baseQuery := `SELECT id, tenant_id, name, description, provider, account_id, service, 
		amount, currency, period, start_time, end_time, created_at, updated_at 
		FROM budgets WHERE tenant_id = $1`

	countQuery := `SELECT COUNT(*) FROM budgets WHERE tenant_id = $1`

	args := []interface{}{tenantID}
	countArgs := []interface{}{tenantID}
	idx := 2

	if provider != "" {
		baseQuery += " AND provider = $" + itoa(idx)
		countQuery += " AND provider = $" + itoa(idx)
		args = append(args, provider)
		countArgs = append(countArgs, provider)
		idx++
	}

	// Add active filter if requested
	if active {
		// Only include budgets where end_time is null or in the future
		baseQuery += " AND (end_time IS NULL OR end_time > NOW())"
		countQuery += " AND (end_time IS NULL OR end_time > NOW())"
	}

	// Add ordering
	baseQuery += " ORDER BY created_at DESC"

	// Add pagination
	limit := 100
	if pageSize > 0 && pageSize <= 100 {
		limit = pageSize
	}

	offset := 0
	if page > 1 {
		offset = (page - 1) * limit
	}

	baseQuery += " LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1)
	args = append(args, limit, offset)

	// Get total count
	r.logger.Debug("Executing count query for budgets",
		logger.String("tenant_id", tenantID),
		logger.Bool("active_only", active),
		logger.Int("arg_count", len(countArgs)))

	row := r.db.QueryRow(ctx, countQuery, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("Failed to get budgets count",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to get budgets count: %w", err)
	}

	// If total is 0, return early
	if total == 0 {
		return []*domain.Budget{}, 0, nil
	}

	// Execute the main query
	r.logger.Debug("Executing query for budgets",
		logger.String("tenant_id", tenantID),
		logger.Int("arg_count", len(args)),
		logger.Int("total_count", total))

	rows, err := r.db.Query(ctx, baseQuery, args...)
	if err != nil {
		r.logger.Error("Failed to query budgets",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to query budgets: %w", err)
	}
	defer rows.Close()

	var results []*domain.Budget
	for rows.Next() {
		var b domain.Budget
		err := rows.Scan(
			&b.ID,
			&b.TenantID,
			&b.Name,
			&b.Description,
			&b.Provider,
			&b.AccountID,
			&b.Service,
			&b.Amount,
			&b.Currency,
			&b.Period,
			&b.StartTime,
			&b.EndTime,
			&b.CreatedAt,
			&b.UpdatedAt,
		)

		if err != nil {
			r.logger.Error("Failed to scan budget row",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
			return nil, 0, fmt.Errorf("failed to scan budget row: %w", err)
		}

		results = append(results, &b)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating over budgets",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("error iterating over budgets: %w", err)
	}

	r.logger.Debug("Successfully retrieved budgets",
		logger.String("tenant_id", tenantID),
		logger.Int("result_count", len(results)),
		logger.Int("total_count", total))

	return results, total, nil
}
