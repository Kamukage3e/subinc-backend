package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// StoreForecast stores a forecast record
func (r *PostgresCostRepository) StoreForecast(ctx context.Context, forecast *domain.Forecast) error {
	if err := validateForecast(forecast); err != nil {
		r.logger.Error("Failed to validate forecast", logger.ErrorField(err), logger.String("forecast_id", forecast.ID))
		return err
	}

	const q = `INSERT INTO forecasts (
		id, tenant_id, provider, account_id, service, resource_type, start_time, 
		end_time, forecasted_cost, actual_cost, currency, confidence, algorithm, 
		created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
	)
	ON CONFLICT (id) DO UPDATE SET
		provider = $3, account_id = $4, service = $5, resource_type = $6, 
		start_time = $7, end_time = $8, forecasted_cost = $9, actual_cost = $10, 
		currency = $11, confidence = $12, algorithm = $13, updated_at = $15`

	_, err := r.db.Exec(ctx, q,
		forecast.ID,
		forecast.TenantID,
		forecast.Provider,
		forecast.AccountID,
		forecast.Service,
		forecast.ResourceType,
		forecast.StartTime,
		forecast.EndTime,
		forecast.ForecastedCost,
		forecast.ActualCost,
		forecast.Currency,
		forecast.Confidence,
		forecast.Algorithm,
		forecast.CreatedAt,
		forecast.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to store forecast",
			logger.ErrorField(err),
			logger.String("forecast_id", forecast.ID),
			logger.String("tenant_id", forecast.TenantID))
		return fmt.Errorf("failed to store forecast: %w", err)
	}

	r.logger.Debug("Successfully stored forecast",
		logger.String("forecast_id", forecast.ID),
		logger.String("tenant_id", forecast.TenantID),
		logger.Float64("forecasted_cost", forecast.ForecastedCost))

	return nil
}

// GetForecast retrieves a forecast by criteria
func (r *PostgresCostRepository) GetForecast(ctx context.Context, tenantID string, provider domain.CloudProvider, accountID string, startTime, endTime time.Time) (*domain.Forecast, error) {
	if tenantID == "" {
		r.logger.Error("Invalid tenant ID for GetForecast", logger.String("tenant_id", tenantID))
		return nil, domain.ErrInvalidTenant
	}

	query := `SELECT id, tenant_id, provider, account_id, service, resource_type, start_time, 
		end_time, forecasted_cost, actual_cost, currency, confidence, algorithm, 
		created_at, updated_at 
		FROM forecasts 
		WHERE tenant_id = $1`

	args := []interface{}{tenantID}

	if provider != "" {
		query += " AND provider = $2"
		args = append(args, provider)
	}

	if accountID != "" {
		query += " AND account_id = $" + itoa(len(args)+1)
		args = append(args, accountID)
	}

	if !startTime.IsZero() {
		query += " AND start_time >= $" + itoa(len(args)+1)
		args = append(args, startTime)
	}

	if !endTime.IsZero() {
		query += " AND end_time <= $" + itoa(len(args)+1)
		args = append(args, endTime)
	}

	// Order by most recent created_at and limit to 1 to get the most recent forecast
	query += " ORDER BY created_at DESC LIMIT 1"

	r.logger.Debug("Executing forecast query",
		logger.String("tenant_id", tenantID),
		logger.String("provider", string(provider)),
		logger.String("account_id", accountID))

	row := r.db.QueryRow(ctx, query, args...)
	var f domain.Forecast
	err := row.Scan(
		&f.ID,
		&f.TenantID,
		&f.Provider,
		&f.AccountID,
		&f.Service,
		&f.ResourceType,
		&f.StartTime,
		&f.EndTime,
		&f.ForecastedCost,
		&f.ActualCost,
		&f.Currency,
		&f.Confidence,
		&f.Algorithm,
		&f.CreatedAt,
		&f.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Forecast not found",
				logger.String("tenant_id", tenantID),
				logger.String("provider", string(provider)),
				logger.String("account_id", accountID))
			return nil, domain.ErrForecastNotFound
		}
		r.logger.Error("Failed to get forecast",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("provider", string(provider)))
		return nil, fmt.Errorf("failed to get forecast: %w", err)
	}

	r.logger.Debug("Successfully retrieved forecast",
		logger.String("forecast_id", f.ID),
		logger.String("tenant_id", f.TenantID),
		logger.Float64("forecasted_cost", f.ForecastedCost))

	return &f, nil
}
