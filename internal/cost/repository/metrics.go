package repository

import (
	"context"
	"time"

	"github.com/subinc/subinc-backend/internal/cost/domain"
)

// MetricsCollector defines the interface for collecting metrics about repository operations
type MetricsCollector interface {
	// RecordDuration records the duration of a repository operation
	RecordDuration(operation string, duration time.Duration, success bool)

	// IncrementCounter increments a counter for a repository operation
	IncrementCounter(operation string, success bool)

	// ObserveValue observes a value for a metric (e.g., batch size, result size)
	ObserveValue(metric string, value float64, labels map[string]string)
}

// PostgresCostRepositoryWithMetrics wraps a PostgresCostRepository with metrics
type PostgresCostRepositoryWithMetrics struct {
	repository *PostgresCostRepository
	metrics    MetricsCollector
}

// executeWithMetrics executes a function and records metrics
func (r *PostgresCostRepositoryWithMetrics) executeWithMetrics(ctx context.Context, operation string, f func(ctx context.Context) error) error {
	startTime := time.Now()
	err := f(ctx)
	duration := time.Since(startTime)
	success := err == nil

	r.metrics.RecordDuration(operation, duration, success)
	r.metrics.IncrementCounter(operation, success)

	return err
}

// executeWithMetricsResult executes a function that returns a result and records metrics
func (r *PostgresCostRepositoryWithMetrics) executeWithMetricsResult(ctx context.Context, operation string, f func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	startTime := time.Now()
	result, err := f(ctx)
	duration := time.Since(startTime)
	success := err == nil

	r.metrics.RecordDuration(operation, duration, success)
	r.metrics.IncrementCounter(operation, success)

	return result, err
}

// StoreCost implements CostRepository.StoreCost with metrics
func (r *PostgresCostRepositoryWithMetrics) StoreCost(ctx context.Context, cost *domain.Cost) error {
	return r.executeWithMetrics(ctx, "StoreCost", func(ctx context.Context) error {
		return r.repository.StoreCost(ctx, cost)
	})
}

// StoreCosts implements CostRepository.StoreCosts with metrics
func (r *PostgresCostRepositoryWithMetrics) StoreCosts(ctx context.Context, costs []*domain.Cost) error {
	r.metrics.ObserveValue("BatchSize", float64(len(costs)), map[string]string{
		"operation": "StoreCosts",
	})

	return r.executeWithMetrics(ctx, "StoreCosts", func(ctx context.Context) error {
		return r.repository.StoreCosts(ctx, costs)
	})
}

// GetCostByID implements CostRepository.GetCostByID with metrics
func (r *PostgresCostRepositoryWithMetrics) GetCostByID(ctx context.Context, id string) (*domain.Cost, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Cost), err
}

// QueryCosts implements CostRepository.QueryCosts with metrics
func (r *PostgresCostRepositoryWithMetrics) QueryCosts(ctx context.Context, query domain.CostQuery) ([]*domain.Cost, int, error) {
	result, err := r.executeWithMetricsResult(ctx, "QueryCosts", func(ctx context.Context) (interface{}, error) {
		costs, total, err := r.repository.QueryCosts(ctx, query)
		if err != nil {
			return nil, err
		}
		return struct {
			costs []*domain.Cost
			total int
		}{costs, total}, nil
	})

	if err != nil {
		return nil, 0, err
	}

	typedResult := result.(struct {
		costs []*domain.Cost
		total int
	})

	r.metrics.ObserveValue("ResultSize", float64(len(typedResult.costs)), map[string]string{
		"operation": "QueryCosts",
	})
	r.metrics.ObserveValue("TotalResults", float64(typedResult.total), map[string]string{
		"operation": "QueryCosts",
	})

	return typedResult.costs, typedResult.total, nil
}

// GetCostSummary implements CostRepository.GetCostSummary with metrics
func (r *PostgresCostRepositoryWithMetrics) GetCostSummary(ctx context.Context, query domain.CostQuery) (*domain.CostSummary, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostSummary", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostSummary(ctx, query)
	})

	if result == nil {
		return nil, err
	}

	summary := result.(*domain.CostSummary)
	if summary != nil {
		r.metrics.ObserveValue("TotalCost", summary.TotalCost, map[string]string{
			"operation": "GetCostSummary",
			"tenant_id": summary.TenantID,
		})
	}

	return summary, err
}

// CreateCostImport implements CostRepository.CreateCostImport with metrics
func (r *PostgresCostRepositoryWithMetrics) CreateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	return r.executeWithMetrics(ctx, "CreateCostImport", func(ctx context.Context) error {
		return r.repository.CreateCostImport(ctx, costImport)
	})
}

// UpdateCostImport implements CostRepository.UpdateCostImport with metrics
func (r *PostgresCostRepositoryWithMetrics) UpdateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	return r.executeWithMetrics(ctx, "UpdateCostImport", func(ctx context.Context) error {
		return r.repository.UpdateCostImport(ctx, costImport)
	})
}

// GetCostImportByID implements CostRepository.GetCostImportByID with metrics
func (r *PostgresCostRepositoryWithMetrics) GetCostImportByID(ctx context.Context, id string) (*domain.CostImport, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostImportByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostImportByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.CostImport), err
}

// ListCostImports implements CostRepository.ListCostImports with metrics
func (r *PostgresCostRepositoryWithMetrics) ListCostImports(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, page, pageSize int) ([]*domain.CostImport, int, error) {
	result, err := r.executeWithMetricsResult(ctx, "ListCostImports", func(ctx context.Context) (interface{}, error) {
		imports, total, err := r.repository.ListCostImports(ctx, tenantID, provider, startTime, endTime, page, pageSize)
		if err != nil {
			return nil, err
		}
		return struct {
			imports []*domain.CostImport
			total   int
		}{imports, total}, nil
	})

	if err != nil {
		return nil, 0, err
	}

	typedResult := result.(struct {
		imports []*domain.CostImport
		total   int
	})

	r.metrics.ObserveValue("ResultSize", float64(len(typedResult.imports)), map[string]string{
		"operation": "ListCostImports",
	})

	return typedResult.imports, typedResult.total, nil
}

// CreateBudget implements CostRepository.CreateBudget with metrics
func (r *PostgresCostRepositoryWithMetrics) CreateBudget(ctx context.Context, budget *domain.Budget) error {
	return r.executeWithMetrics(ctx, "CreateBudget", func(ctx context.Context) error {
		return r.repository.CreateBudget(ctx, budget)
	})
}

// UpdateBudget implements CostRepository.UpdateBudget with metrics
func (r *PostgresCostRepositoryWithMetrics) UpdateBudget(ctx context.Context, budget *domain.Budget) error {
	return r.executeWithMetrics(ctx, "UpdateBudget", func(ctx context.Context) error {
		return r.repository.UpdateBudget(ctx, budget)
	})
}

// DeleteBudget implements CostRepository.DeleteBudget with metrics
func (r *PostgresCostRepositoryWithMetrics) DeleteBudget(ctx context.Context, id string) error {
	return r.executeWithMetrics(ctx, "DeleteBudget", func(ctx context.Context) error {
		return r.repository.DeleteBudget(ctx, id)
	})
}

// GetBudgetByID implements CostRepository.GetBudgetByID with metrics
func (r *PostgresCostRepositoryWithMetrics) GetBudgetByID(ctx context.Context, id string) (*domain.Budget, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetBudgetByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetBudgetByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Budget), err
}

// ListBudgets implements CostRepository.ListBudgets with metrics
func (r *PostgresCostRepositoryWithMetrics) ListBudgets(ctx context.Context, tenantID string, provider domain.CloudProvider, active bool, page, pageSize int) ([]*domain.Budget, int, error) {
	result, err := r.executeWithMetricsResult(ctx, "ListBudgets", func(ctx context.Context) (interface{}, error) {
		budgets, total, err := r.repository.ListBudgets(ctx, tenantID, provider, active, page, pageSize)
		if err != nil {
			return nil, err
		}
		return struct {
			budgets []*domain.Budget
			total   int
		}{budgets, total}, nil
	})

	if err != nil {
		return nil, 0, err
	}

	typedResult := result.(struct {
		budgets []*domain.Budget
		total   int
	})

	r.metrics.ObserveValue("ResultSize", float64(len(typedResult.budgets)), map[string]string{
		"operation": "ListBudgets",
	})

	return typedResult.budgets, typedResult.total, nil
}

// CreateAnomaly implements CostRepository.CreateAnomaly with metrics
func (r *PostgresCostRepositoryWithMetrics) CreateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	return r.executeWithMetrics(ctx, "CreateAnomaly", func(ctx context.Context) error {
		return r.repository.CreateAnomaly(ctx, anomaly)
	})
}

// UpdateAnomaly implements CostRepository.UpdateAnomaly with metrics
func (r *PostgresCostRepositoryWithMetrics) UpdateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	return r.executeWithMetrics(ctx, "UpdateAnomaly", func(ctx context.Context) error {
		return r.repository.UpdateAnomaly(ctx, anomaly)
	})
}

// GetAnomalyByID implements CostRepository.GetAnomalyByID with metrics
func (r *PostgresCostRepositoryWithMetrics) GetAnomalyByID(ctx context.Context, id string) (*domain.Anomaly, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetAnomalyByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetAnomalyByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Anomaly), err
}

// ListAnomalies implements CostRepository.ListAnomalies with metrics
func (r *PostgresCostRepositoryWithMetrics) ListAnomalies(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, status string, page, pageSize int) ([]*domain.Anomaly, int, error) {
	result, err := r.executeWithMetricsResult(ctx, "ListAnomalies", func(ctx context.Context) (interface{}, error) {
		anomalies, total, err := r.repository.ListAnomalies(ctx, tenantID, provider, startTime, endTime, status, page, pageSize)
		if err != nil {
			return nil, err
		}
		return struct {
			anomalies []*domain.Anomaly
			total     int
		}{anomalies, total}, nil
	})

	if err != nil {
		return nil, 0, err
	}

	typedResult := result.(struct {
		anomalies []*domain.Anomaly
		total     int
	})

	r.metrics.ObserveValue("ResultSize", float64(len(typedResult.anomalies)), map[string]string{
		"operation": "ListAnomalies",
	})

	return typedResult.anomalies, typedResult.total, nil
}

// StoreForecast implements CostRepository.StoreForecast with metrics
func (r *PostgresCostRepositoryWithMetrics) StoreForecast(ctx context.Context, forecast *domain.Forecast) error {
	return r.executeWithMetrics(ctx, "StoreForecast", func(ctx context.Context) error {
		return r.repository.StoreForecast(ctx, forecast)
	})
}

// GetForecast implements CostRepository.GetForecast with metrics
func (r *PostgresCostRepositoryWithMetrics) GetForecast(ctx context.Context, tenantID string, provider domain.CloudProvider, accountID string, startTime, endTime time.Time) (*domain.Forecast, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetForecast", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetForecast(ctx, tenantID, provider, accountID, startTime, endTime)
	})

	if result == nil {
		return nil, err
	}

	forecast := result.(*domain.Forecast)
	if forecast != nil {
		r.metrics.ObserveValue("ForecastCost", forecast.ForecastedCost, map[string]string{
			"operation": "GetForecast",
			"tenant_id": forecast.TenantID,
		})
	}

	return forecast, err
}

// HealthCheck implements CostRepository.HealthCheck with metrics
func (r *PostgresCostRepositoryWithMetrics) HealthCheck(ctx context.Context) error {
	return r.executeWithMetrics(ctx, "HealthCheck", func(ctx context.Context) error {
		return r.repository.HealthCheck(ctx)
	})
}
