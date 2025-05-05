package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// CreateAnomaly creates an anomaly record
func (r *PostgresCostRepository) CreateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	if err := validateAnomaly(anomaly); err != nil {
		r.logger.Error("Failed to validate anomaly",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID),
			logger.String("tenant_id", anomaly.TenantID))
		return err
	}

	const q = `INSERT INTO anomalies (
		id, tenant_id, provider, account_id, resource_id, service, detected_at, 
		start_time, end_time, expected_cost, actual_cost, deviation, severity, 
		status, root_cause, recommendation, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
	)`

	_, err := r.db.Exec(ctx, q,
		anomaly.ID,
		anomaly.TenantID,
		anomaly.Provider,
		anomaly.AccountID,
		anomaly.ResourceID,
		anomaly.Service,
		anomaly.DetectedAt,
		anomaly.StartTime,
		anomaly.EndTime,
		anomaly.ExpectedCost,
		anomaly.ActualCost,
		anomaly.Deviation,
		anomaly.Severity,
		anomaly.Status,
		anomaly.RootCause,
		anomaly.Recommendation,
		anomaly.CreatedAt,
		anomaly.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create anomaly",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID),
			logger.String("tenant_id", anomaly.TenantID))
		return fmt.Errorf("failed to create anomaly: %w", err)
	}

	r.logger.Info("Successfully created anomaly",
		logger.String("anomaly_id", anomaly.ID),
		logger.String("tenant_id", anomaly.TenantID),
		logger.String("severity", anomaly.Severity),
		logger.String("status", anomaly.Status),
		logger.Float64("deviation", anomaly.Deviation))

	return nil
}

// UpdateAnomaly updates an anomaly record
func (r *PostgresCostRepository) UpdateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	if err := validateAnomaly(anomaly); err != nil {
		r.logger.Error("Failed to validate anomaly for update",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID),
			logger.String("tenant_id", anomaly.TenantID))
		return err
	}

	const q = `UPDATE anomalies SET 
		provider = $1, account_id = $2, resource_id = $3, service = $4, detected_at = $5, 
		start_time = $6, end_time = $7, expected_cost = $8, actual_cost = $9, 
		deviation = $10, severity = $11, status = $12, root_cause = $13, 
		recommendation = $14, updated_at = $15
		WHERE id = $16 AND tenant_id = $17`

	result, err := r.db.Exec(ctx, q,
		anomaly.Provider,
		anomaly.AccountID,
		anomaly.ResourceID,
		anomaly.Service,
		anomaly.DetectedAt,
		anomaly.StartTime,
		anomaly.EndTime,
		anomaly.ExpectedCost,
		anomaly.ActualCost,
		anomaly.Deviation,
		anomaly.Severity,
		anomaly.Status,
		anomaly.RootCause,
		anomaly.Recommendation,
		anomaly.UpdatedAt,
		anomaly.ID,
		anomaly.TenantID,
	)

	if err != nil {
		r.logger.Error("Failed to update anomaly",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID),
			logger.String("tenant_id", anomaly.TenantID))
		return fmt.Errorf("failed to update anomaly: %w", err)
	}

	// Ensure the record was actually updated
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		r.logger.Warn("No rows affected when updating anomaly",
			logger.String("anomaly_id", anomaly.ID),
			logger.String("tenant_id", anomaly.TenantID))
		return domain.NewEntityNotFoundError("anomaly", anomaly.ID)
	}

	r.logger.Info("Successfully updated anomaly",
		logger.String("anomaly_id", anomaly.ID),
		logger.String("tenant_id", anomaly.TenantID),
		logger.String("status", anomaly.Status))

	return nil
}

// GetAnomalyByID retrieves an anomaly by ID
func (r *PostgresCostRepository) GetAnomalyByID(ctx context.Context, id string) (*domain.Anomaly, error) {
	if id == "" {
		r.logger.Error("Invalid anomaly ID", logger.String("anomaly_id", id))
		return nil, domain.ErrInvalidResource
	}

	const q = `SELECT id, tenant_id, provider, account_id, resource_id, service, detected_at, 
		start_time, end_time, expected_cost, actual_cost, deviation, severity, status, 
		root_cause, recommendation, created_at, updated_at 
		FROM anomalies WHERE id = $1`

	r.logger.Debug("Retrieving anomaly by ID", logger.String("anomaly_id", id))

	row := r.db.QueryRow(ctx, q, id)
	var a domain.Anomaly
	err := row.Scan(
		&a.ID,
		&a.TenantID,
		&a.Provider,
		&a.AccountID,
		&a.ResourceID,
		&a.Service,
		&a.DetectedAt,
		&a.StartTime,
		&a.EndTime,
		&a.ExpectedCost,
		&a.ActualCost,
		&a.Deviation,
		&a.Severity,
		&a.Status,
		&a.RootCause,
		&a.Recommendation,
		&a.CreatedAt,
		&a.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Anomaly not found", logger.String("anomaly_id", id))
			return nil, domain.NewEntityNotFoundError("anomaly", id)
		}

		r.logger.Error("Failed to get anomaly",
			logger.ErrorField(err),
			logger.String("anomaly_id", id))
		return nil, fmt.Errorf("failed to get anomaly: %w", err)
	}

	r.logger.Debug("Successfully retrieved anomaly",
		logger.String("anomaly_id", id),
		logger.String("tenant_id", a.TenantID),
		logger.String("status", a.Status))

	return &a, nil
}

// ListAnomalies lists anomalies
func (r *PostgresCostRepository) ListAnomalies(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, status string, page, pageSize int) ([]*domain.Anomaly, int, error) {
	if tenantID == "" {
		r.logger.Error("Invalid tenant ID for listing anomalies")
		return nil, 0, domain.ErrInvalidTenant
	}

	baseQuery := `SELECT id, tenant_id, provider, account_id, resource_id, service, detected_at, 
		start_time, end_time, expected_cost, actual_cost, deviation, severity, status, 
		root_cause, recommendation, created_at, updated_at 
		FROM anomalies WHERE tenant_id = $1`

	countQuery := `SELECT COUNT(*) FROM anomalies WHERE tenant_id = $1`

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

	if status != "" {
		baseQuery += " AND status = $" + itoa(idx)
		countQuery += " AND status = $" + itoa(idx)
		args = append(args, status)
		countArgs = append(countArgs, status)
		idx++
	}

	// Add ordering
	baseQuery += " ORDER BY detected_at DESC"

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
	r.logger.Debug("Executing count query for anomalies",
		logger.String("tenant_id", tenantID),
		logger.String("status", status),
		logger.Int("arg_count", len(countArgs)))

	row := r.db.QueryRow(ctx, countQuery, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("Failed to get anomalies count",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to get anomalies count: %w", err)
	}

	// If total is 0, return early
	if total == 0 {
		return []*domain.Anomaly{}, 0, nil
	}

	// Execute the main query
	r.logger.Debug("Executing query for anomalies",
		logger.String("tenant_id", tenantID),
		logger.Int("arg_count", len(args)),
		logger.Int("total_count", total))

	rows, err := r.db.Query(ctx, baseQuery, args...)
	if err != nil {
		r.logger.Error("Failed to query anomalies",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to query anomalies: %w", err)
	}
	defer rows.Close()

	var results []*domain.Anomaly
	for rows.Next() {
		var a domain.Anomaly
		err := rows.Scan(
			&a.ID,
			&a.TenantID,
			&a.Provider,
			&a.AccountID,
			&a.ResourceID,
			&a.Service,
			&a.DetectedAt,
			&a.StartTime,
			&a.EndTime,
			&a.ExpectedCost,
			&a.ActualCost,
			&a.Deviation,
			&a.Severity,
			&a.Status,
			&a.RootCause,
			&a.Recommendation,
			&a.CreatedAt,
			&a.UpdatedAt,
		)

		if err != nil {
			r.logger.Error("Failed to scan anomaly row",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
			return nil, 0, fmt.Errorf("failed to scan anomaly row: %w", err)
		}

		results = append(results, &a)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating over anomalies",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("error iterating over anomalies: %w", err)
	}

	r.logger.Debug("Successfully retrieved anomalies",
		logger.String("tenant_id", tenantID),
		logger.Int("result_count", len(results)),
		logger.Int("total_count", total))

	return results, total, nil
}
