package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// CreateCostImport creates a cost import record
func (r *PostgresCostRepository) CreateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	if err := validateCostImport(costImport); err != nil {
		r.logger.Error("Failed to validate cost import",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID),
			logger.String("tenant_id", costImport.TenantID))
		return err
	}

	const q = `INSERT INTO cost_imports (
		id, tenant_id, provider, account_id, start_time, end_time, status, records_count, 
		error_message, created_at, updated_at, completed_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
	)`

	_, err := r.db.Exec(ctx, q,
		costImport.ID,
		costImport.TenantID,
		costImport.Provider,
		costImport.AccountID,
		costImport.StartTime,
		costImport.EndTime,
		costImport.Status,
		costImport.RecordsCount,
		costImport.ErrorMessage,
		costImport.CreatedAt,
		costImport.UpdatedAt,
		costImport.CompletedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create cost import",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID),
			logger.String("tenant_id", costImport.TenantID))
		return fmt.Errorf("failed to create cost import: %w", err)
	}

	r.logger.Info("Successfully created cost import",
		logger.String("import_id", costImport.ID),
		logger.String("tenant_id", costImport.TenantID),
		logger.String("provider", string(costImport.Provider)),
		logger.String("status", costImport.Status))

	return nil
}

// UpdateCostImport updates a cost import record
func (r *PostgresCostRepository) UpdateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	if err := validateCostImport(costImport); err != nil {
		r.logger.Error("Failed to validate cost import for update",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID),
			logger.String("tenant_id", costImport.TenantID))
		return err
	}

	const q = `UPDATE cost_imports SET 
		provider = $1, account_id = $2, start_time = $3, end_time = $4, status = $5, 
		records_count = $6, error_message = $7, updated_at = $8, completed_at = $9
		WHERE id = $10 AND tenant_id = $11`

	result, err := r.db.Exec(ctx, q,
		costImport.Provider,
		costImport.AccountID,
		costImport.StartTime,
		costImport.EndTime,
		costImport.Status,
		costImport.RecordsCount,
		costImport.ErrorMessage,
		costImport.UpdatedAt,
		costImport.CompletedAt,
		costImport.ID,
		costImport.TenantID,
	)

	if err != nil {
		r.logger.Error("Failed to update cost import",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID),
			logger.String("tenant_id", costImport.TenantID))
		return fmt.Errorf("failed to update cost import: %w", err)
	}

	// Ensure the record was actually updated
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		r.logger.Warn("No rows affected when updating cost import",
			logger.String("import_id", costImport.ID),
			logger.String("tenant_id", costImport.TenantID))
		return domain.NewEntityNotFoundError("cost_import", costImport.ID)
	}

	r.logger.Info("Successfully updated cost import",
		logger.String("import_id", costImport.ID),
		logger.String("tenant_id", costImport.TenantID),
		logger.String("status", costImport.Status))

	return nil
}

// GetCostImportByID retrieves a cost import by ID
func (r *PostgresCostRepository) GetCostImportByID(ctx context.Context, id string) (*domain.CostImport, error) {
	if id == "" {
		r.logger.Error("Invalid cost import ID", logger.String("import_id", id))
		return nil, domain.ErrInvalidResource
	}

	const q = `SELECT id, tenant_id, provider, account_id, start_time, end_time, status, 
		records_count, error_message, created_at, updated_at, completed_at 
		FROM cost_imports WHERE id = $1`

	r.logger.Debug("Retrieving cost import by ID", logger.String("import_id", id))

	row := r.db.QueryRow(ctx, q, id)
	var ci domain.CostImport
	err := row.Scan(
		&ci.ID,
		&ci.TenantID,
		&ci.Provider,
		&ci.AccountID,
		&ci.StartTime,
		&ci.EndTime,
		&ci.Status,
		&ci.RecordsCount,
		&ci.ErrorMessage,
		&ci.CreatedAt,
		&ci.UpdatedAt,
		&ci.CompletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Cost import not found", logger.String("import_id", id))
			return nil, domain.NewEntityNotFoundError("cost_import", id)
		}

		r.logger.Error("Failed to get cost import",
			logger.ErrorField(err),
			logger.String("import_id", id))
		return nil, fmt.Errorf("failed to get cost import: %w", err)
	}

	r.logger.Debug("Successfully retrieved cost import",
		logger.String("import_id", id),
		logger.String("tenant_id", ci.TenantID),
		logger.String("status", ci.Status))

	return &ci, nil
}

// ListCostImports lists cost imports
func (r *PostgresCostRepository) ListCostImports(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, page, pageSize int) ([]*domain.CostImport, int, error) {
	if tenantID == "" {
		r.logger.Error("Invalid tenant ID for listing cost imports")
		return nil, 0, domain.ErrInvalidTenant
	}

	baseQuery := `SELECT id, tenant_id, provider, account_id, start_time, end_time, status, 
		records_count, error_message, created_at, updated_at, completed_at 
		FROM cost_imports WHERE tenant_id = $1`

	countQuery := `SELECT COUNT(*) FROM cost_imports WHERE tenant_id = $1`

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

	if !startTime.IsZero() {
		baseQuery += " AND start_time >= $" + itoa(idx)
		countQuery += " AND start_time >= $" + itoa(idx)
		args = append(args, startTime)
		countArgs = append(countArgs, startTime)
		idx++
	}

	if !endTime.IsZero() {
		baseQuery += " AND end_time <= $" + itoa(idx)
		countQuery += " AND end_time <= $" + itoa(idx)
		args = append(args, endTime)
		countArgs = append(countArgs, endTime)
		idx++
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
	r.logger.Debug("Executing count query for cost imports",
		logger.String("tenant_id", tenantID),
		logger.Int("arg_count", len(countArgs)))

	row := r.db.QueryRow(ctx, countQuery, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("Failed to get imports count",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to get imports count: %w", err)
	}

	// If total is 0, return early
	if total == 0 {
		return []*domain.CostImport{}, 0, nil
	}

	// Execute the main query
	r.logger.Debug("Executing query for cost imports",
		logger.String("tenant_id", tenantID),
		logger.Int("arg_count", len(args)),
		logger.Int("total_count", total))

	rows, err := r.db.Query(ctx, baseQuery, args...)
	if err != nil {
		r.logger.Error("Failed to query imports",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to query imports: %w", err)
	}
	defer rows.Close()

	var results []*domain.CostImport
	for rows.Next() {
		var ci domain.CostImport
		err := rows.Scan(
			&ci.ID,
			&ci.TenantID,
			&ci.Provider,
			&ci.AccountID,
			&ci.StartTime,
			&ci.EndTime,
			&ci.Status,
			&ci.RecordsCount,
			&ci.ErrorMessage,
			&ci.CreatedAt,
			&ci.UpdatedAt,
			&ci.CompletedAt,
		)

		if err != nil {
			r.logger.Error("Failed to scan import row",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
			return nil, 0, fmt.Errorf("failed to scan import row: %w", err)
		}

		results = append(results, &ci)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating over imports",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("error iterating over imports: %w", err)
	}

	r.logger.Debug("Successfully retrieved cost imports",
		logger.String("tenant_id", tenantID),
		logger.Int("result_count", len(results)),
		logger.Int("total_count", total))

	return results, total, nil
}
