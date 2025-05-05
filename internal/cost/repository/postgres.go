package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// PostgresCostRepository implements CostRepository using PostgreSQL
type PostgresCostRepository struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

// NewPostgresCostRepository creates a new PostgreSQL-backed cost repository
func NewPostgresCostRepository(db *pgxpool.Pool, log *logger.Logger) (CostRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres connection pool cannot be nil")
	}

	if log == nil {
		log = logger.NewNoop()
	}

	return &PostgresCostRepository{
		db:     db,
		logger: log,
	}, nil
}

// StoreCost stores a single cost record
func (r *PostgresCostRepository) StoreCost(ctx context.Context, cost *domain.Cost) error {
	if err := validateCost(cost); err != nil {
		r.logger.Error("Failed to validate cost", logger.ErrorField(err), logger.String("cost_id", cost.ID))
		return err
	}

	const q = `INSERT INTO costs (
		id, tenant_id, provider, account_id, resource_id, resource_name, resource_type, 
		service, region, usage_type, usage_quantity, usage_unit, cost_amount, cost_currency, 
		effective_price, start_time, end_time, granularity, tags, labels, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
	)`

	_, err := r.db.Exec(ctx, q,
		cost.ID,
		cost.TenantID,
		cost.Provider,
		cost.AccountID,
		cost.ResourceID,
		cost.ResourceName,
		cost.ResourceType,
		cost.Service,
		cost.Region,
		cost.UsageType,
		cost.UsageQuantity,
		cost.UsageUnit,
		cost.CostAmount,
		cost.CostCurrency,
		cost.EffectivePrice,
		cost.StartTime,
		cost.EndTime,
		cost.Granularity,
		cost.Tags,
		cost.Labels,
		cost.CreatedAt,
		cost.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to insert cost record",
			logger.ErrorField(err),
			logger.String("cost_id", cost.ID),
			logger.String("tenant_id", cost.TenantID))
		return fmt.Errorf("failed to insert cost record: %w", err)
	}

	r.logger.Debug("Successfully stored cost record",
		logger.String("cost_id", cost.ID),
		logger.String("tenant_id", cost.TenantID),
		logger.String("provider", string(cost.Provider)),
		logger.Float64("cost_amount", cost.CostAmount))

	return nil
}

// StoreCosts stores multiple cost records
func (r *PostgresCostRepository) StoreCosts(ctx context.Context, costs []*domain.Cost) error {
	if len(costs) == 0 {
		r.logger.Debug("No cost records to store, skipping")
		return nil
	}

	// First validate all costs before starting the transaction
	for i, cost := range costs {
		if err := validateCost(cost); err != nil {
			r.logger.Error("Invalid cost record",
				logger.ErrorField(err),
				logger.String("cost_id", cost.ID),
				logger.String("tenant_id", cost.TenantID),
				logger.Int("index", i))
			return fmt.Errorf("invalid cost record at index %d: %w", i, err)
		}
	}

	// Use a transaction for atomic batch operations
	tx, err := r.db.Begin(ctx)
	if err != nil {
		r.logger.Error("Failed to begin transaction for batch cost storage",
			logger.ErrorField(err),
			logger.Int("batch_size", len(costs)))
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is properly handled
	defer func() {
		if err != nil {
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
				r.logger.Error("Failed to rollback transaction",
					logger.ErrorField(rollbackErr),
					logger.Int("batch_size", len(costs)))
			}
		}
	}()

	// Use a batch for better performance
	batch := &pgx.Batch{}
	const q = `INSERT INTO costs (
		id, tenant_id, provider, account_id, resource_id, resource_name, resource_type, 
		service, region, usage_type, usage_quantity, usage_unit, cost_amount, cost_currency, 
		effective_price, start_time, end_time, granularity, tags, labels, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
	) ON CONFLICT (id) DO UPDATE SET
		provider = $3,
		account_id = $4,
		resource_id = $5,
		resource_name = $6,
		resource_type = $7,
		service = $8,
		region = $9,
		usage_type = $10,
		usage_quantity = $11,
		usage_unit = $12,
		cost_amount = $13,
		cost_currency = $14,
		effective_price = $15,
		start_time = $16,
		end_time = $17,
		granularity = $18,
		tags = $19,
		labels = $20,
		updated_at = $22
	`

	// Group costs by tenant for better logging
	tenantCounts := make(map[string]int)

	// Queue all the inserts
	for _, cost := range costs {
		batch.Queue(q,
			cost.ID,
			cost.TenantID,
			cost.Provider,
			cost.AccountID,
			cost.ResourceID,
			cost.ResourceName,
			cost.ResourceType,
			cost.Service,
			cost.Region,
			cost.UsageType,
			cost.UsageQuantity,
			cost.UsageUnit,
			cost.CostAmount,
			cost.CostCurrency,
			cost.EffectivePrice,
			cost.StartTime,
			cost.EndTime,
			cost.Granularity,
			cost.Tags,
			cost.Labels,
			cost.CreatedAt,
			cost.UpdatedAt,
		)

		tenantCounts[cost.TenantID]++
	}

	// Log batch details
	tenantInfo := ""
	for tenantID, count := range tenantCounts {
		if tenantInfo != "" {
			tenantInfo += ", "
		}
		tenantInfo += fmt.Sprintf("%s:%d", tenantID, count)
	}

	r.logger.Debug("Sending batch of cost records",
		logger.Int("batch_size", batch.Len()),
		logger.String("tenant_counts", tenantInfo))

	// Execute the batch within the transaction
	br := tx.SendBatch(ctx, batch)
	defer br.Close()

	// Process batch results
	var failedIndices []int
	batchErrors := make([]error, 0)

	for i := 0; i < batch.Len(); i++ {
		if _, batchErr := br.Exec(); batchErr != nil {
			failedIndices = append(failedIndices, i)
			batchErrors = append(batchErrors, batchErr)

			r.logger.Error("Failed to execute batch statement",
				logger.ErrorField(batchErr),
				logger.Int("statement_index", i),
				logger.String("cost_id", costs[i].ID),
				logger.String("tenant_id", costs[i].TenantID))

			// Continue processing the batch to identify all failures
		}
	}

	// Handle batch errors
	if len(batchErrors) > 0 {
		// Prepare detailed error message
		errMsg := fmt.Sprintf("%d of %d batch statements failed", len(batchErrors), batch.Len())

		// Combine error information for logging and reporting
		var combinedErr error
		if len(batchErrors) == 1 {
			combinedErr = fmt.Errorf("%s: %w", errMsg, batchErrors[0])
		} else {
			errDetails := ""
			for i, idx := range failedIndices {
				if i > 0 {
					errDetails += ", "
				}
				if i >= 3 {
					errDetails += fmt.Sprintf("and %d more", len(failedIndices)-i)
					break
				}
				errDetails += fmt.Sprintf("index %d (ID: %s)", idx, costs[idx].ID)
			}
			combinedErr = fmt.Errorf("%s (%s)", errMsg, errDetails)
		}

		err = combinedErr
		r.logger.Error("Batch operation failed with multiple errors",
			logger.ErrorField(combinedErr),
			logger.Int("total_failures", len(batchErrors)),
			logger.Int("total_records", len(costs)))

		return err
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		r.logger.Error("Failed to commit transaction",
			logger.ErrorField(err),
			logger.Int("batch_size", len(costs)))
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Successfully stored cost records in batch",
		logger.Int("count", len(costs)),
		logger.String("tenant_counts", tenantInfo))

	return nil
}

// GetCostByID retrieves a cost record by ID
func (r *PostgresCostRepository) GetCostByID(ctx context.Context, id string) (*domain.Cost, error) {
	if id == "" {
		r.logger.Error("Invalid cost ID", logger.String("cost_id", id))
		return nil, domain.ErrInvalidResource
	}

	const q = `SELECT id, tenant_id, provider, account_id, resource_id, resource_name, resource_type, 
		service, region, usage_type, usage_quantity, usage_unit, cost_amount, cost_currency, 
		effective_price, start_time, end_time, granularity, tags, labels, created_at, updated_at 
		FROM costs WHERE id = $1`

	r.logger.Debug("Retrieving cost by ID", logger.String("cost_id", id))

	row := r.db.QueryRow(ctx, q, id)
	var c domain.Cost
	err := row.Scan(
		&c.ID,
		&c.TenantID,
		&c.Provider,
		&c.AccountID,
		&c.ResourceID,
		&c.ResourceName,
		&c.ResourceType,
		&c.Service,
		&c.Region,
		&c.UsageType,
		&c.UsageQuantity,
		&c.UsageUnit,
		&c.CostAmount,
		&c.CostCurrency,
		&c.EffectivePrice,
		&c.StartTime,
		&c.EndTime,
		&c.Granularity,
		&c.Tags,
		&c.Labels,
		&c.CreatedAt,
		&c.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Debug("Cost record not found", logger.String("cost_id", id))
		} else {
			r.logger.Error("Failed to get cost record",
				logger.ErrorField(err),
				logger.String("cost_id", id))
		}
		return nil, mapPostgresError(err, "cost")
	}

	r.logger.Debug("Successfully retrieved cost record",
		logger.String("cost_id", id),
		logger.String("tenant_id", c.TenantID),
		logger.Float64("cost_amount", c.CostAmount))

	return &c, nil
}

// QueryCosts queries cost records based on filter criteria
func (r *PostgresCostRepository) QueryCosts(ctx context.Context, query domain.CostQuery) ([]*domain.Cost, int, error) {
	if err := query.Validate(); err != nil {
		r.logger.Error("Invalid cost query", logger.ErrorField(err))
		return nil, 0, err
	}

	// Safety check for tenant ID
	if query.TenantID == "" {
		r.logger.Error("Missing tenant ID in cost query")
		return nil, 0, domain.ErrInvalidTenant
	}

	// Build SQL dynamically for filters
	baseQuery := `SELECT id, tenant_id, provider, account_id, resource_id, resource_name, resource_type, 
		service, region, usage_type, usage_quantity, usage_unit, cost_amount, cost_currency, 
		effective_price, start_time, end_time, granularity, tags, labels, created_at, updated_at 
		FROM costs WHERE tenant_id = $1`

	countQuery := `SELECT COUNT(*) FROM costs WHERE tenant_id = $1`

	args := []interface{}{query.TenantID}
	countArgs := []interface{}{query.TenantID}
	idx := 2
	countIdx := 2

	// Add filters
	if len(query.Providers) > 0 {
		baseQuery += " AND provider = ANY($" + itoa(idx) + ")"
		countQuery += " AND provider = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.Providers)
		countArgs = append(countArgs, query.Providers)
		idx++
		countIdx++
	}

	if len(query.AccountIDs) > 0 {
		baseQuery += " AND account_id = ANY($" + itoa(idx) + ")"
		countQuery += " AND account_id = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.AccountIDs)
		countArgs = append(countArgs, query.AccountIDs)
		idx++
		countIdx++
	}

	if len(query.ResourceIDs) > 0 {
		baseQuery += " AND resource_id = ANY($" + itoa(idx) + ")"
		countQuery += " AND resource_id = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.ResourceIDs)
		countArgs = append(countArgs, query.ResourceIDs)
		idx++
		countIdx++
	}

	if len(query.ResourceTypes) > 0 {
		baseQuery += " AND resource_type = ANY($" + itoa(idx) + ")"
		countQuery += " AND resource_type = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.ResourceTypes)
		countArgs = append(countArgs, query.ResourceTypes)
		idx++
		countIdx++
	}

	if len(query.Services) > 0 {
		baseQuery += " AND service = ANY($" + itoa(idx) + ")"
		countQuery += " AND service = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.Services)
		countArgs = append(countArgs, query.Services)
		idx++
		countIdx++
	}

	if len(query.Regions) > 0 {
		baseQuery += " AND region = ANY($" + itoa(idx) + ")"
		countQuery += " AND region = ANY($" + itoa(countIdx) + ")"
		args = append(args, query.Regions)
		countArgs = append(countArgs, query.Regions)
		idx++
		countIdx++
	}

	if !query.StartTime.IsZero() {
		baseQuery += " AND start_time >= $" + itoa(idx)
		countQuery += " AND start_time >= $" + itoa(countIdx)
		args = append(args, query.StartTime)
		countArgs = append(countArgs, query.StartTime)
		idx++
		countIdx++
	}

	if !query.EndTime.IsZero() {
		baseQuery += " AND end_time <= $" + itoa(idx)
		countQuery += " AND end_time <= $" + itoa(countIdx)
		args = append(args, query.EndTime)
		countArgs = append(countArgs, query.EndTime)
		idx++
		countIdx++
	}

	if query.Granularity != "" {
		baseQuery += " AND granularity = $" + itoa(idx)
		countQuery += " AND granularity = $" + itoa(countIdx)
		args = append(args, query.Granularity)
		countArgs = append(countArgs, query.Granularity)
		idx++
		countIdx++
	}

	// Handle tags if present
	if len(query.Tags) > 0 {
		for k, v := range query.Tags {
			baseQuery += " AND tags->>" + pgx.Identifier{k}.Sanitize() + " = $" + itoa(idx)
			countQuery += " AND tags->>" + pgx.Identifier{k}.Sanitize() + " = $" + itoa(countIdx)
			args = append(args, v)
			countArgs = append(countArgs, v)
			idx++
			countIdx++
		}
	}

	// Sorting
	order := "created_at DESC"
	if query.SortBy != "" {
		direction := "ASC"
		if strings.ToLower(query.SortDirection) == "desc" {
			direction = "DESC"
		}
		// Sanitize the sort column to prevent SQL injection
		sortColumn := strings.ToLower(query.SortBy)
		validColumns := map[string]bool{
			"cost_amount": true, "start_time": true, "end_time": true,
			"created_at": true, "resource_name": true, "service": true,
		}
		if validColumns[sortColumn] {
			order = sortColumn + " " + direction
		}
	}
	baseQuery += " ORDER BY " + order

	// Pagination
	limit := 100
	if query.PageSize > 0 && query.PageSize <= 1000 {
		limit = query.PageSize
	}

	offset := 0
	if query.Page > 1 {
		offset = (query.Page - 1) * limit
	}

	baseQuery += " LIMIT $" + itoa(idx) + " OFFSET $" + itoa(idx+1)
	args = append(args, limit, offset)

	// Get total count
	r.logger.Debug("Executing count query for costs",
		logger.String("tenant_id", query.TenantID),
		logger.Int("arg_count", len(countArgs)))

	row := r.db.QueryRow(ctx, countQuery, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("Failed to get costs count",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, 0, fmt.Errorf("failed to get costs count: %w", err)
	}

	// If total is 0, return early
	if total == 0 {
		return []*domain.Cost{}, 0, nil
	}

	// Execute the main query
	r.logger.Debug("Executing query for costs",
		logger.String("tenant_id", query.TenantID),
		logger.Int("arg_count", len(args)),
		logger.Int("total_count", total))

	rows, err := r.db.Query(ctx, baseQuery, args...)
	if err != nil {
		r.logger.Error("Failed to query costs",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, 0, fmt.Errorf("failed to query costs: %w", err)
	}
	defer rows.Close()

	var results []*domain.Cost
	for rows.Next() {
		var c domain.Cost
		err := rows.Scan(
			&c.ID,
			&c.TenantID,
			&c.Provider,
			&c.AccountID,
			&c.ResourceID,
			&c.ResourceName,
			&c.ResourceType,
			&c.Service,
			&c.Region,
			&c.UsageType,
			&c.UsageQuantity,
			&c.UsageUnit,
			&c.CostAmount,
			&c.CostCurrency,
			&c.EffectivePrice,
			&c.StartTime,
			&c.EndTime,
			&c.Granularity,
			&c.Tags,
			&c.Labels,
			&c.CreatedAt,
			&c.UpdatedAt,
		)

		if err != nil {
			r.logger.Error("Failed to scan cost row",
				logger.ErrorField(err),
				logger.String("tenant_id", query.TenantID))
			return nil, 0, fmt.Errorf("failed to scan cost row: %w", err)
		}

		results = append(results, &c)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating over cost rows",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, 0, fmt.Errorf("error iterating over cost rows: %w", err)
	}

	r.logger.Debug("Successfully retrieved cost records",
		logger.String("tenant_id", query.TenantID),
		logger.Int("result_count", len(results)),
		logger.Int("total_count", total))

	return results, total, nil
}

// GetCostSummary retrieves cost summary data
func (r *PostgresCostRepository) GetCostSummary(ctx context.Context, query domain.CostQuery) (*domain.CostSummary, error) {
	if err := query.Validate(); err != nil {
		r.logger.Error("Invalid cost query for summary", logger.ErrorField(err))
		return nil, err
	}

	// Build the base query
	baseSelect := "SELECT tenant_id"
	baseFrom := " FROM costs"
	baseWhere := " WHERE tenant_id = $1"
	baseGroupBy := " GROUP BY tenant_id"

	args := []interface{}{query.TenantID}
	idx := 2

	// Add selected columns for grouping
	for _, group := range query.GroupBy {
		// Sanitize and validate group by column to prevent SQL injection
		group = strings.ToLower(group)
		validColumns := map[string]bool{
			"provider": true, "account_id": true, "service": true,
			"resource_type": true, "region": true,
		}

		if validColumns[group] {
			baseSelect += ", " + group
			baseGroupBy += ", " + group
		} else {
			r.logger.Warn("Invalid group by column ignored",
				logger.String("column", group),
				logger.String("tenant_id", query.TenantID))
		}
	}

	// Add aggregation columns
	baseSelect += ", SUM(cost_amount) as total_cost, cost_currency"
	baseGroupBy += ", cost_currency"

	// Add filters
	if len(query.Providers) > 0 {
		baseWhere += " AND provider = ANY($" + itoa(idx) + ")"
		args = append(args, query.Providers)
		idx++
	}

	if len(query.AccountIDs) > 0 {
		baseWhere += " AND account_id = ANY($" + itoa(idx) + ")"
		args = append(args, query.AccountIDs)
		idx++
	}

	if len(query.ResourceTypes) > 0 {
		baseWhere += " AND resource_type = ANY($" + itoa(idx) + ")"
		args = append(args, query.ResourceTypes)
		idx++
	}

	if len(query.Services) > 0 {
		baseWhere += " AND service = ANY($" + itoa(idx) + ")"
		args = append(args, query.Services)
		idx++
	}

	if len(query.Regions) > 0 {
		baseWhere += " AND region = ANY($" + itoa(idx) + ")"
		args = append(args, query.Regions)
		idx++
	}

	if !query.StartTime.IsZero() {
		baseWhere += " AND start_time >= $" + itoa(idx)
		args = append(args, query.StartTime)
		idx++
	}

	if !query.EndTime.IsZero() {
		baseWhere += " AND end_time <= $" + itoa(idx)
		args = append(args, query.EndTime)
		idx++
	}

	if query.Granularity != "" {
		baseWhere += " AND granularity = $" + itoa(idx)
		args = append(args, query.Granularity)
		idx++
	}

	// Handle tags if present
	if len(query.Tags) > 0 {
		for k, v := range query.Tags {
			baseWhere += " AND tags->>" + pgx.Identifier{k}.Sanitize() + " = $" + itoa(idx)
			args = append(args, v)
			idx++
		}
	}

	// Combine the query parts
	fullQuery := baseSelect + baseFrom + baseWhere + baseGroupBy

	r.logger.Debug("Executing cost summary query",
		logger.String("tenant_id", query.TenantID),
		logger.Int("arg_count", len(args)))

	rows, err := r.db.Query(ctx, fullQuery, args...)
	if err != nil {
		r.logger.Error("Failed to query cost summary",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, fmt.Errorf("failed to query cost summary: %w", err)
	}
	defer rows.Close()

	summary := &domain.CostSummary{
		TenantID:    query.TenantID,
		StartTime:   query.StartTime,
		EndTime:     query.EndTime,
		Granularity: query.Granularity,
		GroupBy:     query.GroupBy,
		Groups:      make(map[string]domain.CostSummary),
	}

	// If we're grouping, build a map of groups
	if len(query.GroupBy) > 0 {
		for rows.Next() {
			// Dynamic scanning based on group by columns
			scanDest := make([]interface{}, 3+len(query.GroupBy))

			// First is always tenant_id
			var tenantID string
			scanDest[0] = &tenantID

			// Middle values are the group by columns
			groupValues := make([]string, len(query.GroupBy))
			for i := range query.GroupBy {
				scanDest[i+1] = &groupValues[i]
			}

			// Last two are always total_cost and currency
			var totalCost float64
			var currency string
			scanDest[len(scanDest)-2] = &totalCost
			scanDest[len(scanDest)-1] = &currency

			if err := rows.Scan(scanDest...); err != nil {
				r.logger.Error("Failed to scan cost summary row",
					logger.ErrorField(err),
					logger.String("tenant_id", query.TenantID))
				return nil, fmt.Errorf("failed to scan cost summary row: %w", err)
			}

			// Create a group key
			groupKey := strings.Join(groupValues, "_")

			// Add to the appropriate group in the summary
			groupSummary := domain.CostSummary{
				TenantID:    tenantID,
				TotalCost:   totalCost,
				Currency:    currency,
				StartTime:   query.StartTime,
				EndTime:     query.EndTime,
				Granularity: query.Granularity,
			}

			// Set the group-specific fields
			for i, field := range query.GroupBy {
				switch field {
				case "provider":
					groupSummary.Provider = domain.CloudProvider(groupValues[i])
				case "account_id":
					groupSummary.AccountID = groupValues[i]
				case "service":
					groupSummary.Service = groupValues[i]
				case "resource_type":
					groupSummary.ResourceType = domain.ResourceType(groupValues[i])
				case "region":
					groupSummary.Region = groupValues[i]
				}
			}

			summary.Groups[groupKey] = groupSummary

			// Add to the total
			summary.TotalCost += totalCost
			if summary.Currency == "" && currency != "" {
				summary.Currency = currency
			}
		}
	} else {
		// No grouping, just get the total
		if rows.Next() {
			var tenantID string
			var totalCost float64
			var currency string

			if err := rows.Scan(&tenantID, &totalCost, &currency); err != nil {
				r.logger.Error("Failed to scan cost summary row",
					logger.ErrorField(err),
					logger.String("tenant_id", query.TenantID))
				return nil, fmt.Errorf("failed to scan cost summary row: %w", err)
			}

			summary.TotalCost = totalCost
			summary.Currency = currency
		}
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error iterating over cost summary rows",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, fmt.Errorf("error iterating over cost summary rows: %w", err)
	}

	r.logger.Debug("Successfully retrieved cost summary",
		logger.String("tenant_id", query.TenantID),
		logger.Float64("total_cost", summary.TotalCost),
		logger.String("currency", summary.Currency))

	return summary, nil
}

// HealthCheck performs a connectivity check on the Postgres repository
func (r *PostgresCostRepository) HealthCheck(ctx context.Context) error {
	// Create a deadline for the health check
	ctxTimeout, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Try to ping the database
	if err := r.db.Ping(ctxTimeout); err != nil {
		r.logger.Error("Postgres health check failed",
			logger.ErrorField(err))
		return fmt.Errorf("postgres health check failed: %w", err)
	}

	// Try a simple query to verify the database is responsive
	const query = "SELECT 1"
	row := r.db.QueryRow(ctxTimeout, query)

	var result int
	if err := row.Scan(&result); err != nil {
		r.logger.Error("Postgres health check query failed",
			logger.ErrorField(err))
		return fmt.Errorf("postgres health check query failed: %w", err)
	}

	if result != 1 {
		r.logger.Error("Postgres health check returned unexpected result",
			logger.Int("result", result))
		return fmt.Errorf("postgres health check returned unexpected result: %d", result)
	}

	r.logger.Debug("Postgres health check passed")
	return nil
}

// WithMetrics adds metrics collection to the PostgresCostRepository
func (r *PostgresCostRepository) WithMetrics(metrics MetricsCollector) CostRepository {
	return &PostgresCostRepositoryWithMetrics{
		repository: r,
		metrics:    metrics,
	}
}

// PostgresBillingRepository implements BillingRepository using PostgreSQL
// Only production implementations are supported. No in-memory or dev/test repositories.
type PostgresBillingRepository struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

// NewPostgresBillingRepository creates a new PostgreSQL-backed billing repository
func NewPostgresBillingRepository(db *pgxpool.Pool, log *logger.Logger) (BillingRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres connection pool cannot be nil")
	}
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresBillingRepository{
		db:     db,
		logger: log,
	}, nil
}

// BillingRepository interface implementation (method stubs)
func (r *PostgresBillingRepository) CreateBillingAccount(ctx context.Context, account *domain.BillingAccount) error {
	if account == nil {
		r.logger.Error("nil billing account provided")
		return domain.ErrInvalidTenant
	}
	if err := account.Validate(); err != nil {
		r.logger.Error("invalid billing account", logger.ErrorField(err), logger.String("tenant_id", account.TenantID))
		return err
	}

	const q = `INSERT INTO billing_accounts (
		id, tenant_id, email, created_at, updated_at, is_active
	) VALUES (
		$1, $2, $3, $4, $5, $6
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		account.ID,
		account.TenantID,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
		account.IsActive,
	)
	if err != nil {
		r.logger.Error("failed to insert billing account", logger.ErrorField(err), logger.String("account_id", account.ID), logger.String("tenant_id", account.TenantID))
		return fmt.Errorf("failed to insert billing account: %w", err)
	}

	r.logger.Info("successfully created billing account", logger.String("account_id", account.ID), logger.String("tenant_id", account.TenantID))
	return nil
}

func (r *PostgresBillingRepository) UpdateBillingAccount(ctx context.Context, account *domain.BillingAccount) error {
	if account == nil {
		r.logger.Error("nil billing account provided")
		return domain.ErrInvalidTenant
	}
	if err := account.Validate(); err != nil {
		r.logger.Error("invalid billing account", logger.ErrorField(err), logger.String("tenant_id", account.TenantID))
		return err
	}

	const q = `UPDATE billing_accounts SET
		tenant_id = $2,
		email = $3,
		created_at = $4,
		updated_at = $5,
		is_active = $6
	WHERE id = $1`

	cmd, err := r.db.Exec(ctx, q,
		account.ID,
		account.TenantID,
		account.Email,
		account.CreatedAt,
		account.UpdatedAt,
		account.IsActive,
	)
	if err != nil {
		r.logger.Error("failed to update billing account", logger.ErrorField(err), logger.String("account_id", account.ID), logger.String("tenant_id", account.TenantID))
		return fmt.Errorf("failed to update billing account: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no billing account updated (not found)", logger.String("account_id", account.ID), logger.String("tenant_id", account.TenantID))
		return domain.ErrInvalidTenant
	}

	r.logger.Info("successfully updated billing account", logger.String("account_id", account.ID), logger.String("tenant_id", account.TenantID))
	return nil
}

func (r *PostgresBillingRepository) GetBillingAccountByID(ctx context.Context, id string) (*domain.BillingAccount, error) {
	if id == "" {
		r.logger.Error("empty billing account id provided")
		return nil, domain.ErrInvalidTenant
	}

	const q = `SELECT id, tenant_id, email, created_at, updated_at, is_active FROM billing_accounts WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var a domain.BillingAccount
	if err := row.Scan(&a.ID, &a.TenantID, &a.Email, &a.CreatedAt, &a.UpdatedAt, &a.IsActive); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("billing account not found", logger.String("account_id", id))
			return nil, domain.ErrInvalidTenant
		}
		r.logger.Error("failed to get billing account", logger.ErrorField(err), logger.String("account_id", id))
		return nil, fmt.Errorf("failed to get billing account: %w", err)
	}

	r.logger.Info("successfully retrieved billing account", logger.String("account_id", a.ID), logger.String("tenant_id", a.TenantID))
	return &a, nil
}

func (r *PostgresBillingRepository) ListBillingAccounts(ctx context.Context, tenantID string, page, pageSize int) ([]*domain.BillingAccount, int, error) {
	if tenantID == "" {
		r.logger.Error("empty tenant id provided for list billing accounts")
		return nil, 0, domain.ErrInvalidTenant
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const countQ = `SELECT COUNT(*) FROM billing_accounts WHERE tenant_id = $1`
	row := r.db.QueryRow(ctx, countQ, tenantID)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count billing accounts", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to count billing accounts: %w", err)
	}
	if total == 0 {
		return []*domain.BillingAccount{}, 0, nil
	}
	const q = `SELECT id, tenant_id, email, created_at, updated_at, is_active FROM billing_accounts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, q, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		r.logger.Error("failed to list billing accounts", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("failed to list billing accounts: %w", err)
	}
	defer rows.Close()
	var accounts []*domain.BillingAccount
	for rows.Next() {
		var a domain.BillingAccount
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Email, &a.CreatedAt, &a.UpdatedAt, &a.IsActive); err != nil {
			r.logger.Error("failed to scan billing account row", logger.ErrorField(err), logger.String("tenant_id", tenantID))
			return nil, 0, fmt.Errorf("failed to scan billing account row: %w", err)
		}
		accounts = append(accounts, &a)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating billing account rows", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, 0, fmt.Errorf("error iterating billing account rows: %w", err)
	}

	r.logger.Info("successfully listed billing accounts", logger.String("tenant_id", tenantID), logger.Int("count", len(accounts)), logger.Int("total", total))
	return accounts, total, nil
}

func (r *PostgresBillingRepository) CreateBillingPlan(ctx context.Context, plan *domain.BillingPlan) error {
	if plan == nil {
		r.logger.Error("nil billing plan provided")
		return domain.ErrInvalidPlan
	}
	if err := plan.Validate(); err != nil {
		r.logger.Error("invalid billing plan", logger.ErrorField(err), logger.String("plan_name", plan.Name))
		return err
	}

	const q = `INSERT INTO billing_plans (
		id, name, description, is_active, created_at, updated_at, pricing
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		plan.ID,
		plan.Name,
		plan.Description,
		plan.IsActive,
		plan.CreatedAt,
		plan.UpdatedAt,
		plan.Pricing,
	)
	if err != nil {
		r.logger.Error("failed to insert billing plan", logger.ErrorField(err), logger.String("plan_id", plan.ID), logger.String("plan_name", plan.Name))
		return fmt.Errorf("failed to insert billing plan: %w", err)
	}

	r.logger.Info("successfully created billing plan", logger.String("plan_id", plan.ID), logger.String("plan_name", plan.Name))
	return nil
}

func (r *PostgresBillingRepository) UpdateBillingPlan(ctx context.Context, plan *domain.BillingPlan) error {
	if plan == nil {
		r.logger.Error("nil billing plan provided")
		return domain.ErrInvalidPlan
	}
	if err := plan.Validate(); err != nil {
		r.logger.Error("invalid billing plan", logger.ErrorField(err), logger.String("plan_name", plan.Name))
		return err
	}

	const q = `UPDATE billing_plans SET
		name = $2,
		description = $3,
		is_active = $4,
		created_at = $5,
		updated_at = $6,
		pricing = $7
	WHERE id = $1`

	cmd, err := r.db.Exec(ctx, q,
		plan.ID,
		plan.Name,
		plan.Description,
		plan.IsActive,
		plan.CreatedAt,
		plan.UpdatedAt,
		plan.Pricing,
	)
	if err != nil {
		r.logger.Error("failed to update billing plan", logger.ErrorField(err), logger.String("plan_id", plan.ID), logger.String("plan_name", plan.Name))
		return fmt.Errorf("failed to update billing plan: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no billing plan updated (not found)", logger.String("plan_id", plan.ID), logger.String("plan_name", plan.Name))
		return domain.ErrInvalidPlan
	}

	r.logger.Info("successfully updated billing plan", logger.String("plan_id", plan.ID), logger.String("plan_name", plan.Name))
	return nil
}

func (r *PostgresBillingRepository) GetBillingPlanByID(ctx context.Context, id string) (*domain.BillingPlan, error) {
	if id == "" {
		r.logger.Error("empty billing plan id provided")
		return nil, domain.ErrInvalidPlan
	}

	const q = `SELECT id, name, description, is_active, created_at, updated_at, pricing FROM billing_plans WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var p domain.BillingPlan
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.IsActive, &p.CreatedAt, &p.UpdatedAt, &p.Pricing); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("billing plan not found", logger.String("plan_id", id))
			return nil, domain.ErrInvalidPlan
		}
		r.logger.Error("failed to get billing plan", logger.ErrorField(err), logger.String("plan_id", id))
		return nil, fmt.Errorf("failed to get billing plan: %w", err)
	}

	r.logger.Info("successfully retrieved billing plan", logger.String("plan_id", p.ID), logger.String("plan_name", p.Name))
	return &p, nil
}

func (r *PostgresBillingRepository) ListBillingPlans(ctx context.Context, activeOnly bool, page, pageSize int) ([]*domain.BillingPlan, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	countQ := `SELECT COUNT(*) FROM billing_plans`
	q := `SELECT id, name, description, is_active, created_at, updated_at, pricing FROM billing_plans`
	where := ""
	if activeOnly {
		where = " WHERE is_active = true"
	}
	countQ += where
	q += where + " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
	// Get total count
	row := r.db.QueryRow(ctx, countQ)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count billing plans", logger.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to count billing plans: %w", err)
	}
	if total == 0 {
		return []*domain.BillingPlan{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, pageSize, (page-1)*pageSize)
	if err != nil {
		r.logger.Error("failed to list billing plans", logger.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to list billing plans: %w", err)
	}
	defer rows.Close()
	var plans []*domain.BillingPlan
	for rows.Next() {
		var p domain.BillingPlan
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.IsActive, &p.CreatedAt, &p.UpdatedAt, &p.Pricing); err != nil {
			r.logger.Error("failed to scan billing plan row", logger.ErrorField(err))
			return nil, 0, fmt.Errorf("failed to scan billing plan row: %w", err)
		}
		plans = append(plans, &p)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating billing plan rows", logger.ErrorField(err))
		return nil, 0, fmt.Errorf("error iterating billing plan rows: %w", err)
	}

	r.logger.Info("successfully listed billing plans", logger.Int("count", len(plans)), logger.Int("total", total), logger.Bool("active_only", activeOnly))
	return plans, total, nil
}

func (r *PostgresBillingRepository) CreateUsageEvent(ctx context.Context, event *domain.UsageEvent) error {
	if event == nil {
		r.logger.Error("nil usage event provided")
		return domain.ErrInvalidUsage
	}
	if err := event.Validate(); err != nil {
		r.logger.Error("invalid usage event", logger.ErrorField(err), logger.String("account_id", event.AccountID))
		return err
	}

	const q = `INSERT INTO usage_events (
		id, account_id, resource, quantity, unit, timestamp, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		event.ID,
		event.AccountID,
		event.Resource,
		event.Quantity,
		event.Unit,
		event.Timestamp,
		event.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert usage event", logger.ErrorField(err), logger.String("event_id", event.ID), logger.String("account_id", event.AccountID))
		return fmt.Errorf("failed to insert usage event: %w", err)
	}

	r.logger.Info("successfully created usage event", logger.String("event_id", event.ID), logger.String("account_id", event.AccountID))
	return nil
}

func (r *PostgresBillingRepository) ListUsageEvents(ctx context.Context, accountID string, startTime, endTime time.Time, page, pageSize int) ([]*domain.UsageEvent, int, error) {
	if accountID == "" {
		r.logger.Error("empty account id provided for list usage events")
		return nil, 0, domain.ErrInvalidUsage
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	countQ := `SELECT COUNT(*) FROM usage_events WHERE account_id = $1 AND timestamp >= $2 AND timestamp <= $3`
	row := r.db.QueryRow(ctx, countQ, accountID, startTime, endTime)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count usage events", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to count usage events: %w", err)
	}
	if total == 0 {
		return []*domain.UsageEvent{}, 0, nil
	}
	q := `SELECT id, account_id, resource, quantity, unit, timestamp, metadata FROM usage_events WHERE account_id = $1 AND timestamp >= $2 AND timestamp <= $3 ORDER BY timestamp DESC LIMIT $4 OFFSET $5`
	rows, err := r.db.Query(ctx, q, accountID, startTime, endTime, pageSize, (page-1)*pageSize)
	if err != nil {
		r.logger.Error("failed to list usage events", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to list usage events: %w", err)
	}
	defer rows.Close()
	var events []*domain.UsageEvent
	for rows.Next() {
		var e domain.UsageEvent
		if err := rows.Scan(&e.ID, &e.AccountID, &e.Resource, &e.Quantity, &e.Unit, &e.Timestamp, &e.Metadata); err != nil {
			r.logger.Error("failed to scan usage event row", logger.ErrorField(err), logger.String("account_id", accountID))
			return nil, 0, fmt.Errorf("failed to scan usage event row: %w", err)
		}
		events = append(events, &e)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating usage event rows", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("error iterating usage event rows: %w", err)
	}

	r.logger.Info("successfully listed usage events", logger.String("account_id", accountID), logger.Int("count", len(events)), logger.Int("total", total))
	return events, total, nil
}

// ... rest of the code ...

func (r *PostgresBillingRepository) CreateInvoice(ctx context.Context, invoice *domain.Invoice) error {
	if invoice == nil {
		r.logger.Error("nil invoice provided")
		return domain.ErrInvalidInvoice
	}
	if err := invoice.Validate(); err != nil {
		r.logger.Error("invalid invoice", logger.ErrorField(err), logger.String("account_id", invoice.AccountID))
		return err
	}

	const q = `INSERT INTO invoices (
		id, account_id, period_start, period_end, amount, currency, status, created_at, updated_at, paid_at, line_items
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		invoice.ID,
		invoice.AccountID,
		invoice.PeriodStart,
		invoice.PeriodEnd,
		invoice.Amount,
		invoice.Currency,
		invoice.Status,
		invoice.CreatedAt,
		invoice.UpdatedAt,
		invoice.PaidAt,
		invoice.LineItems,
	)
	if err != nil {
		r.logger.Error("failed to insert invoice", logger.ErrorField(err), logger.String("invoice_id", invoice.ID), logger.String("account_id", invoice.AccountID))
		return fmt.Errorf("failed to insert invoice: %w", err)
	}

	r.logger.Info("successfully created invoice", logger.String("invoice_id", invoice.ID), logger.String("account_id", invoice.AccountID))
	return nil
}

func (r *PostgresBillingRepository) UpdateInvoice(ctx context.Context, invoice *domain.Invoice) error {
	if invoice == nil {
		r.logger.Error("nil invoice provided")
		return domain.ErrInvalidInvoice
	}
	if err := invoice.Validate(); err != nil {
		r.logger.Error("invalid invoice", logger.ErrorField(err), logger.String("account_id", invoice.AccountID))
		return err
	}

	const q = `UPDATE invoices SET
		account_id = $2,
		period_start = $3,
		period_end = $4,
		amount = $5,
		currency = $6,
		status = $7,
		created_at = $8,
		updated_at = $9,
		paid_at = $10,
		line_items = $11
	WHERE id = $1`

	cmd, err := r.db.Exec(ctx, q,
		invoice.ID,
		invoice.AccountID,
		invoice.PeriodStart,
		invoice.PeriodEnd,
		invoice.Amount,
		invoice.Currency,
		invoice.Status,
		invoice.CreatedAt,
		invoice.UpdatedAt,
		invoice.PaidAt,
		invoice.LineItems,
	)
	if err != nil {
		r.logger.Error("failed to update invoice", logger.ErrorField(err), logger.String("invoice_id", invoice.ID), logger.String("account_id", invoice.AccountID))
		return fmt.Errorf("failed to update invoice: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no invoice updated (not found)", logger.String("invoice_id", invoice.ID), logger.String("account_id", invoice.AccountID))
		return domain.ErrInvalidInvoice
	}

	r.logger.Info("successfully updated invoice", logger.String("invoice_id", invoice.ID), logger.String("account_id", invoice.AccountID))
	return nil
}

func (r *PostgresBillingRepository) GetInvoiceByID(ctx context.Context, id string) (*domain.Invoice, error) {
	if id == "" {
		r.logger.Error("empty invoice id provided")
		return nil, domain.ErrInvalidInvoice
	}

	const q = `SELECT id, account_id, period_start, period_end, amount, currency, status, created_at, updated_at, paid_at, line_items FROM invoices WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var inv domain.Invoice
	if err := row.Scan(&inv.ID, &inv.AccountID, &inv.PeriodStart, &inv.PeriodEnd, &inv.Amount, &inv.Currency, &inv.Status, &inv.CreatedAt, &inv.UpdatedAt, &inv.PaidAt, &inv.LineItems); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("invoice not found", logger.String("invoice_id", id))
			return nil, domain.ErrInvalidInvoice
		}
		r.logger.Error("failed to get invoice", logger.ErrorField(err), logger.String("invoice_id", id))
		return nil, fmt.Errorf("failed to get invoice: %w", err)
	}

	r.logger.Info("successfully retrieved invoice", logger.String("invoice_id", inv.ID), logger.String("account_id", inv.AccountID))
	return &inv, nil
}

func (r *PostgresBillingRepository) ListInvoices(ctx context.Context, accountID string, status string, page, pageSize int) ([]*domain.Invoice, int, error) {
	if accountID == "" {
		r.logger.Error("empty account id provided for list invoices")
		return nil, 0, domain.ErrInvalidInvoice
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	countQ := `SELECT COUNT(*) FROM invoices WHERE account_id = $1`
	q := `SELECT id, account_id, period_start, period_end, amount, currency, status, created_at, updated_at, paid_at, line_items FROM invoices WHERE account_id = $1`
	args := []interface{}{accountID}
	if status != "" {
		countQ += " AND status = $2"
		q += " AND status = $2"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	row := r.db.QueryRow(ctx, countQ, args...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count invoices", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to count invoices: %w", err)
	}
	if total == 0 {
		return []*domain.Invoice{}, 0, nil
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list invoices", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to list invoices: %w", err)
	}
	defer rows.Close()
	var invoices []*domain.Invoice
	for rows.Next() {
		var inv domain.Invoice
		if err := rows.Scan(&inv.ID, &inv.AccountID, &inv.PeriodStart, &inv.PeriodEnd, &inv.Amount, &inv.Currency, &inv.Status, &inv.CreatedAt, &inv.UpdatedAt, &inv.PaidAt, &inv.LineItems); err != nil {
			r.logger.Error("failed to scan invoice row", logger.ErrorField(err), logger.String("account_id", accountID))
			return nil, 0, fmt.Errorf("failed to scan invoice row: %w", err)
		}
		invoices = append(invoices, &inv)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating invoice rows", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("error iterating invoice rows: %w", err)
	}

	r.logger.Info("successfully listed invoices", logger.String("account_id", accountID), logger.Int("count", len(invoices)), logger.Int("total", total), logger.String("status", status))
	return invoices, total, nil
}

func (r *PostgresBillingRepository) CreatePayment(ctx context.Context, payment *domain.Payment) error {
	if payment == nil {
		r.logger.Error("nil payment provided")
		return domain.ErrInvalidPayment
	}
	if err := payment.Validate(); err != nil {
		r.logger.Error("invalid payment", logger.ErrorField(err), logger.String("invoice_id", payment.InvoiceID))
		return err
	}

	const q = `INSERT INTO payments (
		id, invoice_id, amount, currency, provider, status, created_at, updated_at, reference
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		payment.ID,
		payment.InvoiceID,
		payment.Amount,
		payment.Currency,
		payment.Provider,
		payment.Status,
		payment.CreatedAt,
		payment.UpdatedAt,
		payment.Reference,
	)
	if err != nil {
		r.logger.Error("failed to insert payment", logger.ErrorField(err), logger.String("payment_id", payment.ID), logger.String("invoice_id", payment.InvoiceID))
		return fmt.Errorf("failed to insert payment: %w", err)
	}

	r.logger.Info("successfully created payment", logger.String("payment_id", payment.ID), logger.String("invoice_id", payment.InvoiceID))
	return nil
}

func (r *PostgresBillingRepository) UpdatePayment(ctx context.Context, payment *domain.Payment) error {
	if payment == nil {
		r.logger.Error("nil payment provided")
		return domain.ErrInvalidPayment
	}
	if err := payment.Validate(); err != nil {
		r.logger.Error("invalid payment", logger.ErrorField(err), logger.String("invoice_id", payment.InvoiceID))
		return err
	}

	const q = `UPDATE payments SET
		invoice_id = $2,
		amount = $3,
		currency = $4,
		provider = $5,
		status = $6,
		created_at = $7,
		updated_at = $8,
		reference = $9
	WHERE id = $1`

	cmd, err := r.db.Exec(ctx, q,
		payment.ID,
		payment.InvoiceID,
		payment.Amount,
		payment.Currency,
		payment.Provider,
		payment.Status,
		payment.CreatedAt,
		payment.UpdatedAt,
		payment.Reference,
	)
	if err != nil {
		r.logger.Error("failed to update payment", logger.ErrorField(err), logger.String("payment_id", payment.ID), logger.String("invoice_id", payment.InvoiceID))
		return fmt.Errorf("failed to update payment: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no payment updated (not found)", logger.String("payment_id", payment.ID), logger.String("invoice_id", payment.InvoiceID))
		return domain.ErrInvalidPayment
	}

	r.logger.Info("successfully updated payment", logger.String("payment_id", payment.ID), logger.String("invoice_id", payment.InvoiceID))
	return nil
}

func (r *PostgresBillingRepository) GetPaymentByID(ctx context.Context, id string) (*domain.Payment, error) {
	if id == "" {
		r.logger.Error("empty payment id provided")
		return nil, domain.ErrInvalidPayment
	}

	const q = `SELECT id, invoice_id, amount, currency, provider, status, created_at, updated_at, reference FROM payments WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var p domain.Payment
	if err := row.Scan(&p.ID, &p.InvoiceID, &p.Amount, &p.Currency, &p.Provider, &p.Status, &p.CreatedAt, &p.UpdatedAt, &p.Reference); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("payment not found", logger.String("payment_id", id))
			return nil, domain.ErrInvalidPayment
		}
		r.logger.Error("failed to get payment", logger.ErrorField(err), logger.String("payment_id", id))
		return nil, fmt.Errorf("failed to get payment: %w", err)
	}

	r.logger.Info("successfully retrieved payment", logger.String("payment_id", p.ID), logger.String("invoice_id", p.InvoiceID))
	return &p, nil
}

func (r *PostgresBillingRepository) ListPayments(ctx context.Context, invoiceID string, page, pageSize int) ([]*domain.Payment, int, error) {
	if invoiceID == "" {
		r.logger.Error("empty invoice id provided for list payments")
		return nil, 0, domain.ErrInvalidPayment
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const countQ = `SELECT COUNT(*) FROM payments WHERE invoice_id = $1`
	row := r.db.QueryRow(ctx, countQ, invoiceID)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count payments", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, 0, fmt.Errorf("failed to count payments: %w", err)
	}
	if total == 0 {
		return []*domain.Payment{}, 0, nil
	}
	const q = `SELECT id, invoice_id, amount, currency, provider, status, created_at, updated_at, reference FROM payments WHERE invoice_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Query(ctx, q, invoiceID, pageSize, (page-1)*pageSize)
	if err != nil {
		r.logger.Error("failed to list payments", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, 0, fmt.Errorf("failed to list payments: %w", err)
	}
	defer rows.Close()
	var payments []*domain.Payment
	for rows.Next() {
		var p domain.Payment
		if err := rows.Scan(&p.ID, &p.InvoiceID, &p.Amount, &p.Currency, &p.Provider, &p.Status, &p.CreatedAt, &p.UpdatedAt, &p.Reference); err != nil {
			r.logger.Error("failed to scan payment row", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
			return nil, 0, fmt.Errorf("failed to scan payment row: %w", err)
		}
		payments = append(payments, &p)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating payment rows", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, 0, fmt.Errorf("error iterating payment rows: %w", err)
	}

	r.logger.Info("successfully listed payments", logger.String("invoice_id", invoiceID), logger.Int("count", len(payments)), logger.Int("total", total))
	return payments, total, nil
}

func (r *PostgresBillingRepository) CreateAuditLog(ctx context.Context, logEntry *domain.AuditLog) error {
	if logEntry == nil {
		r.logger.Error("nil audit log provided")
		return domain.ErrInvalidAuditLog
	}
	if err := logEntry.Validate(); err != nil {
		r.logger.Error("invalid audit log", logger.ErrorField(err), logger.String("actor_id", logEntry.ActorID))
		return err
	}

	const q = `INSERT INTO audit_logs (
		id, actor_id, action, target_id, timestamp, details
	) VALUES (
		$1, $2, $3, $4, $5, $6
	) ON CONFLICT (id) DO NOTHING`

	_, err := r.db.Exec(ctx, q,
		logEntry.ID,
		logEntry.ActorID,
		logEntry.Action,
		logEntry.TargetID,
		logEntry.Timestamp,
		logEntry.Details,
	)
	if err != nil {
		r.logger.Error("failed to insert audit log", logger.ErrorField(err), logger.String("audit_log_id", logEntry.ID), logger.String("actor_id", logEntry.ActorID))
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	r.logger.Info("successfully created audit log", logger.String("audit_log_id", logEntry.ID), logger.String("actor_id", logEntry.ActorID))
	return nil
}

func (r *PostgresBillingRepository) ListAuditLogs(ctx context.Context, accountID string, action string, startTime, endTime time.Time, page, pageSize int) ([]*domain.AuditLog, int, error) {
	if accountID == "" {
		r.logger.Error("empty account id provided for list audit logs")
		return nil, 0, domain.ErrInvalidAuditLog
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	countQ := `SELECT COUNT(*) FROM audit_logs WHERE target_id = $1 AND timestamp >= $2 AND timestamp <= $3`
	q := `SELECT id, actor_id, action, target_id, timestamp, details FROM audit_logs WHERE target_id = $1 AND timestamp >= $2 AND timestamp <= $3`
	args := []interface{}{accountID, startTime, endTime}
	if action != "" {
		countQ += " AND action = $4"
		q += " AND action = $4"
		args = append(args, action)
	}
	q += " ORDER BY timestamp DESC LIMIT $5 OFFSET $6"
	row := r.db.QueryRow(ctx, countQ, args...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count audit logs", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	if total == 0 {
		return []*domain.AuditLog{}, 0, nil
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list audit logs", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()
	var logs []*domain.AuditLog
	for rows.Next() {
		var l domain.AuditLog
		if err := rows.Scan(&l.ID, &l.ActorID, &l.Action, &l.TargetID, &l.Timestamp, &l.Details); err != nil {
			r.logger.Error("failed to scan audit log row", logger.ErrorField(err), logger.String("account_id", accountID))
			return nil, 0, fmt.Errorf("failed to scan audit log row: %w", err)
		}
		logs = append(logs, &l)
	}
	if err = rows.Err(); err != nil {
		r.logger.Error("error iterating audit log rows", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, 0, fmt.Errorf("error iterating audit log rows: %w", err)
	}

	r.logger.Info("successfully listed audit logs", logger.String("account_id", accountID), logger.Int("count", len(logs)), logger.Int("total", total), logger.String("action", action))
	return logs, total, nil
}

// Discount CRUD
func (r *PostgresBillingRepository) CreateDiscount(ctx context.Context, discount *domain.Discount) error {
	if discount == nil {
		r.logger.Error("nil discount provided")
		return domain.NewValidationError("discount", "must not be nil")
	}
	if err := discount.Validate(); err != nil {
		r.logger.Error("invalid discount", logger.ErrorField(err), logger.String("code", discount.Code))
		return err
	}
	const q = `INSERT INTO discounts (
		id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
	)`
	_, err := r.db.Exec(ctx, q,
		discount.ID,
		discount.Code,
		discount.Type,
		discount.Value,
		discount.MaxRedemptions,
		discount.Redeemed,
		discount.StartAt,
		discount.EndAt,
		discount.IsActive,
		discount.CreatedAt,
		discount.UpdatedAt,
		discount.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert discount", logger.ErrorField(err), logger.String("code", discount.Code))
		if strings.Contains(err.Error(), "unique constraint") {
			return domain.NewValidationError("code", "must be unique")
		}
		return err
	}
	r.logger.Info("successfully created discount", logger.String("discount_id", discount.ID), logger.String("code", discount.Code))
	return nil
}

func (r *PostgresBillingRepository) UpdateDiscount(ctx context.Context, discount *domain.Discount) error {
	if discount == nil {
		r.logger.Error("nil discount provided")
		return domain.NewValidationError("discount", "must not be nil")
	}
	if err := discount.Validate(); err != nil {
		r.logger.Error("invalid discount", logger.ErrorField(err), logger.String("code", discount.Code))
		return err
	}
	const q = `UPDATE discounts SET
		code = $2, type = $3, value = $4, max_redemptions = $5, redeemed = $6, start_at = $7, end_at = $8, is_active = $9, created_at = $10, updated_at = $11, metadata = $12
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		discount.ID,
		discount.Code,
		discount.Type,
		discount.Value,
		discount.MaxRedemptions,
		discount.Redeemed,
		discount.StartAt,
		discount.EndAt,
		discount.IsActive,
		discount.CreatedAt,
		discount.UpdatedAt,
		discount.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update discount", logger.ErrorField(err), logger.String("discount_id", discount.ID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no discount updated (not found)", logger.String("discount_id", discount.ID))
		return domain.NewDiscountNotFoundError(discount.ID)
	}
	r.logger.Info("successfully updated discount", logger.String("discount_id", discount.ID))
	return nil
}

func (r *PostgresBillingRepository) DeleteDiscount(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty discount id provided for delete")
		return domain.NewValidationError("id", "must not be empty")
	}
	const q = `DELETE FROM discounts WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete discount", logger.ErrorField(err), logger.String("discount_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no discount deleted (not found)", logger.String("discount_id", id))
		return domain.NewDiscountNotFoundError(id)
	}
	r.logger.Info("successfully deleted discount", logger.String("discount_id", id))
	return nil
}

func (r *PostgresBillingRepository) GetDiscountByID(ctx context.Context, id string) (*domain.Discount, error) {
	if id == "" {
		r.logger.Error("empty discount id provided for get")
		return nil, domain.NewValidationError("id", "must not be empty")
	}
	const q = `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var d domain.Discount
	if err := row.Scan(&d.ID, &d.Code, &d.Type, &d.Value, &d.MaxRedemptions, &d.Redeemed, &d.StartAt, &d.EndAt, &d.IsActive, &d.CreatedAt, &d.UpdatedAt, &d.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("discount not found", logger.String("discount_id", id))
			return nil, domain.NewDiscountNotFoundError(id)
		}
		r.logger.Error("failed to get discount", logger.ErrorField(err), logger.String("discount_id", id))
		return nil, err
	}
	return &d, nil
}

func (r *PostgresBillingRepository) GetDiscountByCode(ctx context.Context, code string) (*domain.Discount, error) {
	if code == "" {
		r.logger.Error("empty discount code provided for get")
		return nil, domain.NewValidationError("code", "must not be empty")
	}
	const q = `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts WHERE code = $1`
	row := r.db.QueryRow(ctx, q, code)
	var d domain.Discount
	if err := row.Scan(&d.ID, &d.Code, &d.Type, &d.Value, &d.MaxRedemptions, &d.Redeemed, &d.StartAt, &d.EndAt, &d.IsActive, &d.CreatedAt, &d.UpdatedAt, &d.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("discount not found by code", logger.String("code", code))
			return nil, domain.NewDiscountNotFoundError(code)
		}
		r.logger.Error("failed to get discount by code", logger.ErrorField(err), logger.String("code", code))
		return nil, err
	}
	return &d, nil
}

func (r *PostgresBillingRepository) ListDiscounts(ctx context.Context, isActive *bool, page, pageSize int) ([]*domain.Discount, int, error) {
	const baseQ = `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts`
	const countQ = `SELECT COUNT(*) FROM discounts`
	var where []string
	var args []interface{}
	var countArgs []interface{}
	idx := 1
	if isActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *isActive)
		countArgs = append(countArgs, *isActive)
		idx++
	}
	q := baseQ
	cq := countQ
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
		cq += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT $" + fmt.Sprint(idx) + " OFFSET $" + fmt.Sprint(idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	countArgs = append(countArgs, args[:len(args)-2]...)
	row := r.db.QueryRow(ctx, cq, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count discounts", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.Discount{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list discounts", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var discounts []*domain.Discount
	for rows.Next() {
		var d domain.Discount
		if err := rows.Scan(&d.ID, &d.Code, &d.Type, &d.Value, &d.MaxRedemptions, &d.Redeemed, &d.StartAt, &d.EndAt, &d.IsActive, &d.CreatedAt, &d.UpdatedAt, &d.Metadata); err != nil {
			r.logger.Error("failed to scan discount row", logger.ErrorField(err))
			return nil, 0, err
		}
		discounts = append(discounts, &d)
	}
	return discounts, total, nil
}

// Coupon CRUD
func (r *PostgresBillingRepository) CreateCoupon(ctx context.Context, coupon *domain.Coupon) error {
	if coupon == nil {
		r.logger.Error("nil coupon provided")
		return domain.NewValidationError("coupon", "must not be nil")
	}
	if err := coupon.Validate(); err != nil {
		r.logger.Error("invalid coupon", logger.ErrorField(err), logger.String("code", coupon.Code))
		return err
	}
	const q = `INSERT INTO coupons (
		id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
	)`
	_, err := r.db.Exec(ctx, q,
		coupon.ID,
		coupon.Code,
		coupon.DiscountID,
		coupon.MaxRedemptions,
		coupon.Redeemed,
		coupon.StartAt,
		coupon.EndAt,
		coupon.IsActive,
		coupon.CreatedAt,
		coupon.UpdatedAt,
		coupon.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert coupon", logger.ErrorField(err), logger.String("code", coupon.Code))
		if strings.Contains(err.Error(), "unique constraint") {
			return domain.NewValidationError("code", "must be unique")
		}
		return err
	}
	r.logger.Info("successfully created coupon", logger.String("coupon_id", coupon.ID), logger.String("code", coupon.Code))
	return nil
}

func (r *PostgresBillingRepository) UpdateCoupon(ctx context.Context, coupon *domain.Coupon) error {
	if coupon == nil {
		r.logger.Error("nil coupon provided")
		return domain.NewValidationError("coupon", "must not be nil")
	}
	if err := coupon.Validate(); err != nil {
		r.logger.Error("invalid coupon", logger.ErrorField(err), logger.String("code", coupon.Code))
		return err
	}
	const q = `UPDATE coupons SET
		code = $2, discount_id = $3, max_redemptions = $4, redeemed = $5, start_at = $6, end_at = $7, is_active = $8, created_at = $9, updated_at = $10, metadata = $11
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		coupon.ID,
		coupon.Code,
		coupon.DiscountID,
		coupon.MaxRedemptions,
		coupon.Redeemed,
		coupon.StartAt,
		coupon.EndAt,
		coupon.IsActive,
		coupon.CreatedAt,
		coupon.UpdatedAt,
		coupon.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update coupon", logger.ErrorField(err), logger.String("coupon_id", coupon.ID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no coupon updated (not found)", logger.String("coupon_id", coupon.ID))
		return domain.NewCouponNotFoundError(coupon.ID)
	}
	r.logger.Info("successfully updated coupon", logger.String("coupon_id", coupon.ID))
	return nil
}

func (r *PostgresBillingRepository) DeleteCoupon(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty coupon id provided for delete")
		return domain.NewValidationError("id", "must not be empty")
	}
	const q = `DELETE FROM coupons WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete coupon", logger.ErrorField(err), logger.String("coupon_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no coupon deleted (not found)", logger.String("coupon_id", id))
		return domain.NewCouponNotFoundError(id)
	}
	r.logger.Info("successfully deleted coupon", logger.String("coupon_id", id))
	return nil
}

func (r *PostgresBillingRepository) GetCouponByID(ctx context.Context, id string) (*domain.Coupon, error) {
	if id == "" {
		r.logger.Error("empty coupon id provided for get")
		return nil, domain.NewValidationError("id", "must not be empty")
	}
	const q = `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var c domain.Coupon
	if err := row.Scan(&c.ID, &c.Code, &c.DiscountID, &c.MaxRedemptions, &c.Redeemed, &c.StartAt, &c.EndAt, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("coupon not found", logger.String("coupon_id", id))
			return nil, domain.NewCouponNotFoundError(id)
		}
		r.logger.Error("failed to get coupon", logger.ErrorField(err), logger.String("coupon_id", id))
		return nil, err
	}
	return &c, nil
}

func (r *PostgresBillingRepository) GetCouponByCode(ctx context.Context, code string) (*domain.Coupon, error) {
	if code == "" {
		r.logger.Error("empty coupon code provided for get")
		return nil, domain.NewValidationError("code", "must not be empty")
	}
	const q = `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons WHERE code = $1`
	row := r.db.QueryRow(ctx, q, code)
	var c domain.Coupon
	if err := row.Scan(&c.ID, &c.Code, &c.DiscountID, &c.MaxRedemptions, &c.Redeemed, &c.StartAt, &c.EndAt, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("coupon not found by code", logger.String("code", code))
			return nil, domain.NewCouponNotFoundError(code)
		}
		r.logger.Error("failed to get coupon by code", logger.ErrorField(err), logger.String("code", code))
		return nil, err
	}
	return &c, nil
}

func (r *PostgresBillingRepository) ListCoupons(ctx context.Context, discountID string, isActive *bool, page, pageSize int) ([]*domain.Coupon, int, error) {
	const baseQ = `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons`
	const countQ = `SELECT COUNT(*) FROM coupons`
	var where []string
	var args []interface{}
	var countArgs []interface{}
	idx := 1
	if discountID != "" {
		where = append(where, fmt.Sprintf("discount_id = $%d", idx))
		args = append(args, discountID)
		countArgs = append(countArgs, discountID)
		idx++
	}
	if isActive != nil {
		where = append(where, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *isActive)
		countArgs = append(countArgs, *isActive)
		idx++
	}
	q := baseQ
	cq := countQ
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
		cq += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT $" + fmt.Sprint(idx) + " OFFSET $" + fmt.Sprint(idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	countArgs = append(countArgs, args[:len(args)-2]...)
	row := r.db.QueryRow(ctx, cq, countArgs...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count coupons", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.Coupon{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list coupons", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var coupons []*domain.Coupon
	for rows.Next() {
		var c domain.Coupon
		if err := rows.Scan(&c.ID, &c.Code, &c.DiscountID, &c.MaxRedemptions, &c.Redeemed, &c.StartAt, &c.EndAt, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
			r.logger.Error("failed to scan coupon row", logger.ErrorField(err))
			return nil, 0, err
		}
		coupons = append(coupons, &c)
	}
	return coupons, total, nil
}

// --- Credit CRUD ---
func (r *PostgresBillingRepository) CreateCredit(ctx context.Context, credit *domain.Credit) error {
	if credit == nil {
		r.logger.Error("nil credit provided")
		return domain.NewValidationError("credit", "must not be nil")
	}
	if err := credit.Validate(); err != nil {
		r.logger.Error("invalid credit", logger.ErrorField(err), logger.String("account_id", credit.AccountID))
		return err
	}
	const q = `INSERT INTO credits (
		id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata 
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
	)`
	_, err := r.db.Exec(ctx, q,
		credit.ID,
		credit.AccountID,
		credit.InvoiceID,
		credit.Amount,
		credit.Currency,
		credit.Type,
		credit.Status,
		credit.CreatedAt,
		credit.UpdatedAt,
		credit.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to create credit", logger.ErrorField(err), logger.String("credit_id", credit.ID))
		return err
	}
	r.logger.Info("successfully created credit", logger.String("credit_id", credit.ID))
	return nil
}

func (r *PostgresBillingRepository) UpdateCredit(ctx context.Context, credit *domain.Credit) error {
	if credit == nil {
		r.logger.Error("nil credit provided")
		return domain.NewValidationError("credit", "must not be nil")
	}
	if err := credit.Validate(); err != nil {
		r.logger.Error("invalid credit", logger.ErrorField(err), logger.String("account_id", credit.AccountID))
		return err
	}
	const q = `UPDATE credits SET
		account_id = $2,
		invoice_id = $3,
		amount = $4,
		currency = $5,
		type = $6,
		status = $7,
		created_at = $8,
		updated_at = $9,
		metadata = $10
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		credit.ID,
		credit.AccountID,
		credit.InvoiceID,
		credit.Amount,
		credit.Currency,
		credit.Type,
		credit.Status,
		credit.CreatedAt,
		credit.UpdatedAt,
		credit.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update credit", logger.ErrorField(err), logger.String("credit_id", credit.ID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no credit updated (not found)", logger.String("credit_id", credit.ID))
		return domain.NewValidationError("credit", "not found")
	}
	r.logger.Info("successfully updated credit", logger.String("credit_id", credit.ID))
	return nil
}

func (r *PostgresBillingRepository) DeleteCredit(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty credit id provided")
		return domain.NewValidationError("credit_id", "must not be empty")
	}
	const q = `DELETE FROM credits WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete credit", logger.ErrorField(err), logger.String("credit_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no credit deleted (not found)", logger.String("credit_id", id))
		return domain.NewValidationError("credit", "not found")
	}
	r.logger.Info("successfully deleted credit", logger.String("credit_id", id))
	return nil
}

func (r *PostgresBillingRepository) GetCreditByID(ctx context.Context, id string) (*domain.Credit, error) {
	if id == "" {
		r.logger.Error("empty credit id provided")
		return nil, domain.NewValidationError("credit_id", "must not be empty")
	}
	const q = `SELECT id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata FROM credits WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var cr domain.Credit
	if err := row.Scan(&cr.ID, &cr.AccountID, &cr.InvoiceID, &cr.Amount, &cr.Currency, &cr.Type, &cr.Status, &cr.CreatedAt, &cr.UpdatedAt, &cr.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("credit not found", logger.String("credit_id", id))
			return nil, domain.NewValidationError("credit", "not found")
		}
		r.logger.Error("failed to get credit", logger.ErrorField(err), logger.String("credit_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved credit", logger.String("credit_id", cr.ID), logger.String("account_id", cr.AccountID))
	return &cr, nil
}

// --- Subscription CRUD ---
func (r *PostgresBillingRepository) CreateSubscription(ctx context.Context, sub *domain.Subscription) error {
	if sub == nil {
		r.logger.Error("nil subscription provided")
		return domain.NewValidationError("subscription", "must not be nil")
	}
	if err := sub.Validate(); err != nil {
		r.logger.Error("invalid subscription", logger.ErrorField(err), logger.String("account_id", sub.AccountID))
		return err
	}
	const q = `INSERT INTO subscriptions (
		id, account_id, plan_id, status, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
	) ON CONFLICT (id) DO NOTHING`
	_, err := r.db.Exec(ctx, q,
		sub.ID,
		sub.AccountID,
		sub.PlanID,
		sub.Status,
		sub.TrialStart,
		sub.TrialEnd,
		sub.CurrentPeriodStart,
		sub.CurrentPeriodEnd,
		sub.CancelAt,
		sub.CanceledAt,
		sub.GracePeriodEnd,
		sub.DunningUntil,
		sub.ScheduledPlanID,
		sub.ScheduledChangeAt,
		sub.CreatedAt,
		sub.UpdatedAt,
		sub.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert subscription", logger.ErrorField(err), logger.String("subscription_id", sub.ID), logger.String("account_id", sub.AccountID))
		return err
	}
	r.logger.Info("successfully created subscription", logger.String("subscription_id", sub.ID), logger.String("account_id", sub.AccountID))
	return nil
}

func (r *PostgresBillingRepository) UpdateSubscription(ctx context.Context, sub *domain.Subscription) error {
	if sub == nil {
		r.logger.Error("nil subscription provided")
		return domain.NewValidationError("subscription", "must not be nil")
	}
	if err := sub.Validate(); err != nil {
		r.logger.Error("invalid subscription", logger.ErrorField(err), logger.String("account_id", sub.AccountID))
		return err
	}
	const q = `UPDATE subscriptions SET
		account_id = $2,
		plan_id = $3,
		status = $4,
		trial_start = $5,
		trial_end = $6,
		current_period_start = $7,
		current_period_end = $8,
		cancel_at = $9,
		canceled_at = $10,
		grace_period_end = $11,
		dunning_until = $12,
		scheduled_plan_id = $13,
		scheduled_change_at = $14,
		created_at = $15,
		updated_at = $16,
		metadata = $17
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		sub.ID,
		sub.AccountID,
		sub.PlanID,
		sub.Status,
		sub.TrialStart,
		sub.TrialEnd,
		sub.CurrentPeriodStart,
		sub.CurrentPeriodEnd,
		sub.CancelAt,
		sub.CanceledAt,
		sub.GracePeriodEnd,
		sub.DunningUntil,
		sub.ScheduledPlanID,
		sub.ScheduledChangeAt,
		sub.CreatedAt,
		sub.UpdatedAt,
		sub.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update subscription", logger.ErrorField(err), logger.String("subscription_id", sub.ID), logger.String("account_id", sub.AccountID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no subscription updated (not found)", logger.String("subscription_id", sub.ID), logger.String("account_id", sub.AccountID))
		return domain.NewValidationError("subscription", "not found")
	}
	r.logger.Info("successfully updated subscription", logger.String("subscription_id", sub.ID), logger.String("account_id", sub.AccountID))
	return nil
}

func (r *PostgresBillingRepository) DeleteSubscription(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty subscription id provided")
		return domain.NewValidationError("subscription_id", "must not be empty")
	}
	const q = `DELETE FROM subscriptions WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete subscription", logger.ErrorField(err), logger.String("subscription_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no subscription deleted (not found)", logger.String("subscription_id", id))
		return domain.NewValidationError("subscription", "not found")
	}
	r.logger.Info("successfully deleted subscription", logger.String("subscription_id", id))
	return nil
}

func (r *PostgresBillingRepository) GetSubscriptionByID(ctx context.Context, id string) (*domain.Subscription, error) {
	if id == "" {
		r.logger.Error("empty subscription id provided")
		return nil, domain.NewValidationError("subscription_id", "must not be empty")
	}
	const q = `SELECT id, account_id, plan_id, status, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata FROM subscriptions WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var s domain.Subscription
	if err := row.Scan(&s.ID, &s.AccountID, &s.PlanID, &s.Status, &s.TrialStart, &s.TrialEnd, &s.CurrentPeriodStart, &s.CurrentPeriodEnd, &s.CancelAt, &s.CanceledAt, &s.GracePeriodEnd, &s.DunningUntil, &s.ScheduledPlanID, &s.ScheduledChangeAt, &s.CreatedAt, &s.UpdatedAt, &s.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("subscription not found", logger.String("subscription_id", id))
			return nil, domain.NewValidationError("subscription", "not found")
		}
		r.logger.Error("failed to get subscription", logger.ErrorField(err), logger.String("subscription_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved subscription", logger.String("subscription_id", s.ID), logger.String("account_id", s.AccountID))
	return &s, nil
}

func (r *PostgresBillingRepository) ListSubscriptions(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.Subscription, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if accountID != "" {
		where = append(where, fmt.Sprintf("account_id = $%d", idx))
		args = append(args, accountID)
		idx++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, status)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM subscriptions"
	q := "SELECT id, account_id, plan_id, status, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata FROM subscriptions"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count subscriptions", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.Subscription{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list subscriptions", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var subs []*domain.Subscription
	for rows.Next() {
		var s domain.Subscription
		if err := rows.Scan(&s.ID, &s.AccountID, &s.PlanID, &s.Status, &s.TrialStart, &s.TrialEnd, &s.CurrentPeriodStart, &s.CurrentPeriodEnd, &s.CancelAt, &s.CanceledAt, &s.GracePeriodEnd, &s.DunningUntil, &s.ScheduledPlanID, &s.ScheduledChangeAt, &s.CreatedAt, &s.UpdatedAt, &s.Metadata); err != nil {
			r.logger.Error("failed to scan subscription row", logger.ErrorField(err))
			return nil, 0, err
		}
		subs = append(subs, &s)
	}
	return subs, total, nil
}

// --- WebhookEvent CRUD ---
func (r *PostgresBillingRepository) CreateWebhookEvent(ctx context.Context, event *domain.WebhookEvent) error {
	if event == nil {
		r.logger.Error("nil webhook event provided")
		return domain.NewValidationError("webhook_event", "must not be nil")
	}
	if err := event.Validate(); err != nil {
		r.logger.Error("invalid webhook event", logger.ErrorField(err), logger.String("provider", event.Provider))
		return err
	}
	const q = `INSERT INTO webhook_events (
		id, provider, event_type, payload, status, received_at, processed_at, error, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9
	) ON CONFLICT (id) DO NOTHING`
	_, err := r.db.Exec(ctx, q,
		event.ID,
		event.Provider,
		event.EventType,
		event.Payload,
		event.Status,
		event.ReceivedAt,
		event.ProcessedAt,
		event.Error,
		event.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert webhook event", logger.ErrorField(err), logger.String("webhook_event_id", event.ID), logger.String("provider", event.Provider))
		return err
	}
	r.logger.Info("successfully created webhook event", logger.String("webhook_event_id", event.ID), logger.String("provider", event.Provider))
	return nil
}

func (r *PostgresBillingRepository) UpdateWebhookEvent(ctx context.Context, event *domain.WebhookEvent) error {
	if event == nil {
		r.logger.Error("nil webhook event provided")
		return domain.NewValidationError("webhook_event", "must not be nil")
	}
	if err := event.Validate(); err != nil {
		r.logger.Error("invalid webhook event", logger.ErrorField(err), logger.String("provider", event.Provider))
		return err
	}
	const q = `UPDATE webhook_events SET
		provider = $2,
		event_type = $3,
		payload = $4,
		status = $5,
		received_at = $6,
		processed_at = $7,
		error = $8,
		metadata = $9
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		event.ID,
		event.Provider,
		event.EventType,
		event.Payload,
		event.Status,
		event.ReceivedAt,
		event.ProcessedAt,
		event.Error,
		event.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update webhook event", logger.ErrorField(err), logger.String("webhook_event_id", event.ID), logger.String("provider", event.Provider))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no webhook event updated (not found)", logger.String("webhook_event_id", event.ID), logger.String("provider", event.Provider))
		return domain.NewValidationError("webhook_event", "not found")
	}
	r.logger.Info("successfully updated webhook event", logger.String("webhook_event_id", event.ID), logger.String("provider", event.Provider))
	return nil
}

func (r *PostgresBillingRepository) GetWebhookEventByID(ctx context.Context, id string) (*domain.WebhookEvent, error) {
	if id == "" {
		r.logger.Error("empty webhook event id provided")
		return nil, domain.NewValidationError("webhook_event_id", "must not be empty")
	}
	const q = `SELECT id, provider, event_type, payload, status, received_at, processed_at, error, metadata FROM webhook_events WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var e domain.WebhookEvent
	if err := row.Scan(&e.ID, &e.Provider, &e.EventType, &e.Payload, &e.Status, &e.ReceivedAt, &e.ProcessedAt, &e.Error, &e.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("webhook event not found", logger.String("webhook_event_id", id))
			return nil, domain.NewValidationError("webhook_event", "not found")
		}
		r.logger.Error("failed to get webhook event", logger.ErrorField(err), logger.String("webhook_event_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved webhook event", logger.String("webhook_event_id", e.ID), logger.String("provider", e.Provider))
	return &e, nil
}

func (r *PostgresBillingRepository) ListWebhookEvents(ctx context.Context, provider, status, eventType string, page, pageSize int) ([]*domain.WebhookEvent, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if provider != "" {
		where = append(where, fmt.Sprintf("provider = $%d", idx))
		args = append(args, provider)
		idx++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, status)
		idx++
	}
	if eventType != "" {
		where = append(where, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, eventType)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM webhook_events"
	q := "SELECT id, provider, event_type, payload, status, received_at, processed_at, error, metadata FROM webhook_events"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY received_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count webhook events", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.WebhookEvent{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list webhook events", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var events []*domain.WebhookEvent
	for rows.Next() {
		var e domain.WebhookEvent
		if err := rows.Scan(&e.ID, &e.Provider, &e.EventType, &e.Payload, &e.Status, &e.ReceivedAt, &e.ProcessedAt, &e.Error, &e.Metadata); err != nil {
			r.logger.Error("failed to scan webhook event row", logger.ErrorField(err))
			return nil, 0, err
		}
		events = append(events, &e)
	}
	return events, total, nil
}

// --- InvoiceAdjustment CRUD ---
func (r *PostgresBillingRepository) CreateInvoiceAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error {
	if adj == nil {
		r.logger.Error("nil invoice adjustment provided")
		return domain.NewValidationError("invoice_adjustment", "must not be nil")
	}
	if err := adj.Validate(); err != nil {
		r.logger.Error("invalid invoice adjustment", logger.ErrorField(err), logger.String("invoice_id", adj.InvoiceID))
		return err
	}
	const q = `INSERT INTO invoice_adjustments (
		id, invoice_id, type, amount, currency, reason, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9
	) ON CONFLICT (id) DO NOTHING`
	_, err := r.db.Exec(ctx, q,
		adj.ID,
		adj.InvoiceID,
		adj.Type,
		adj.Amount,
		adj.Currency,
		adj.Reason,
		adj.CreatedAt,
		adj.UpdatedAt,
		adj.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert invoice adjustment", logger.ErrorField(err), logger.String("invoice_adjustment_id", adj.ID), logger.String("invoice_id", adj.InvoiceID))
		return err
	}
	r.logger.Info("successfully created invoice adjustment", logger.String("invoice_adjustment_id", adj.ID), logger.String("invoice_id", adj.InvoiceID))
	return nil
}

func (r *PostgresBillingRepository) UpdateInvoiceAdjustment(ctx context.Context, adj *domain.InvoiceAdjustment) error {
	if adj == nil {
		r.logger.Error("nil invoice adjustment provided")
		return domain.NewValidationError("invoice_adjustment", "must not be nil")
	}
	if err := adj.Validate(); err != nil {
		r.logger.Error("invalid invoice adjustment", logger.ErrorField(err), logger.String("invoice_id", adj.InvoiceID))
		return err
	}
	const q = `UPDATE invoice_adjustments SET
		invoice_id = $2,
		type = $3,
		amount = $4,
		currency = $5,
		reason = $6,
		created_at = $7,
		updated_at = $8,
		metadata = $9
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		adj.ID,
		adj.InvoiceID,
		adj.Type,
		adj.Amount,
		adj.Currency,
		adj.Reason,
		adj.CreatedAt,
		adj.UpdatedAt,
		adj.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update invoice adjustment", logger.ErrorField(err), logger.String("invoice_adjustment_id", adj.ID), logger.String("invoice_id", adj.InvoiceID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no invoice adjustment updated (not found)", logger.String("invoice_adjustment_id", adj.ID), logger.String("invoice_id", adj.InvoiceID))
		return domain.NewValidationError("invoice_adjustment", "not found")
	}
	r.logger.Info("successfully updated invoice adjustment", logger.String("invoice_adjustment_id", adj.ID), logger.String("invoice_id", adj.InvoiceID))
	return nil
}

func (r *PostgresBillingRepository) GetInvoiceAdjustmentByID(ctx context.Context, id string) (*domain.InvoiceAdjustment, error) {
	if id == "" {
		r.logger.Error("empty invoice adjustment id provided")
		return nil, domain.NewValidationError("invoice_adjustment_id", "must not be empty")
	}
	const q = `SELECT id, invoice_id, type, amount, currency, reason, created_at, updated_at, metadata FROM invoice_adjustments WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var a domain.InvoiceAdjustment
	if err := row.Scan(&a.ID, &a.InvoiceID, &a.Type, &a.Amount, &a.Currency, &a.Reason, &a.CreatedAt, &a.UpdatedAt, &a.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("invoice adjustment not found", logger.String("invoice_adjustment_id", id))
			return nil, domain.NewValidationError("invoice_adjustment", "not found")
		}
		r.logger.Error("failed to get invoice adjustment", logger.ErrorField(err), logger.String("invoice_adjustment_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved invoice adjustment", logger.String("invoice_adjustment_id", a.ID), logger.String("invoice_id", a.InvoiceID))
	return &a, nil
}

func (r *PostgresBillingRepository) ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]*domain.InvoiceAdjustment, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if invoiceID != "" {
		where = append(where, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, invoiceID)
		idx++
	}
	if adjType != "" {
		where = append(where, fmt.Sprintf("type = $%d", idx))
		args = append(args, adjType)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM invoice_adjustments"
	q := "SELECT id, invoice_id, type, amount, currency, reason, created_at, updated_at, metadata FROM invoice_adjustments"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count invoice adjustments", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.InvoiceAdjustment{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list invoice adjustments", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var adjs []*domain.InvoiceAdjustment
	for rows.Next() {
		var a domain.InvoiceAdjustment
		if err := rows.Scan(&a.ID, &a.InvoiceID, &a.Type, &a.Amount, &a.Currency, &a.Reason, &a.CreatedAt, &a.UpdatedAt, &a.Metadata); err != nil {
			r.logger.Error("failed to scan invoice adjustment row", logger.ErrorField(err))
			return nil, 0, err
		}
		adjs = append(adjs, &a)
	}
	return adjs, total, nil
}

// --- PaymentMethod CRUD ---
func (r *PostgresBillingRepository) CreatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error {
	if method == nil {
		r.logger.Error("nil payment method provided")
		return domain.NewValidationError("payment_method", "must not be nil")
	}
	if err := method.Validate(); err != nil {
		r.logger.Error("invalid payment method", logger.ErrorField(err), logger.String("account_id", method.AccountID))
		return err
	}
	const q = `INSERT INTO payment_methods (
		id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
	) ON CONFLICT (id) DO NOTHING`
	_, err := r.db.Exec(ctx, q,
		method.ID,
		method.AccountID,
		method.Type,
		method.Provider,
		method.Last4,
		method.ExpMonth,
		method.ExpYear,
		method.IsDefault,
		method.Status,
		method.CreatedAt,
		method.UpdatedAt,
		method.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert payment method", logger.ErrorField(err), logger.String("payment_method_id", method.ID), logger.String("account_id", method.AccountID))
		return err
	}
	r.logger.Info("successfully created payment method", logger.String("payment_method_id", method.ID), logger.String("account_id", method.AccountID))
	return nil
}

func (r *PostgresBillingRepository) UpdatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error {
	if method == nil {
		r.logger.Error("nil payment method provided")
		return domain.NewValidationError("payment_method", "must not be nil")
	}
	if err := method.Validate(); err != nil {
		r.logger.Error("invalid payment method", logger.ErrorField(err), logger.String("account_id", method.AccountID))
		return err
	}
	const q = `UPDATE payment_methods SET
		account_id = $2,
		type = $3,
		provider = $4,
		last4 = $5,
		exp_month = $6,
		exp_year = $7,
		is_default = $8,
		status = $9,
		created_at = $10,
		updated_at = $11,
		metadata = $12
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		method.ID,
		method.AccountID,
		method.Type,
		method.Provider,
		method.Last4,
		method.ExpMonth,
		method.ExpYear,
		method.IsDefault,
		method.Status,
		method.CreatedAt,
		method.UpdatedAt,
		method.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update payment method", logger.ErrorField(err), logger.String("payment_method_id", method.ID), logger.String("account_id", method.AccountID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no payment method updated (not found)", logger.String("payment_method_id", method.ID), logger.String("account_id", method.AccountID))
		return domain.NewValidationError("payment_method", "not found")
	}
	r.logger.Info("successfully updated payment method", logger.String("payment_method_id", method.ID), logger.String("account_id", method.AccountID))
	return nil
}

func (r *PostgresBillingRepository) DeletePaymentMethod(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty payment method id provided")
		return domain.NewValidationError("payment_method_id", "must not be empty")
	}
	const q = `DELETE FROM payment_methods WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete payment method", logger.ErrorField(err), logger.String("payment_method_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no payment method deleted (not found)", logger.String("payment_method_id", id))
		return domain.NewValidationError("payment_method", "not found")
	}
	r.logger.Info("successfully deleted payment method", logger.String("payment_method_id", id))
	return nil
}

func (r *PostgresBillingRepository) GetPaymentMethodByID(ctx context.Context, id string) (*domain.PaymentMethod, error) {
	if id == "" {
		r.logger.Error("empty payment method id provided")
		return nil, domain.NewValidationError("payment_method_id", "must not be empty")
	}
	const q = `SELECT id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, created_at, updated_at, metadata FROM payment_methods WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var pm domain.PaymentMethod
	if err := row.Scan(&pm.ID, &pm.AccountID, &pm.Type, &pm.Provider, &pm.Last4, &pm.ExpMonth, &pm.ExpYear, &pm.IsDefault, &pm.Status, &pm.CreatedAt, &pm.UpdatedAt, &pm.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("payment method not found", logger.String("payment_method_id", id))
			return nil, domain.NewValidationError("payment_method", "not found")
		}
		r.logger.Error("failed to get payment method", logger.ErrorField(err), logger.String("payment_method_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved payment method", logger.String("payment_method_id", pm.ID), logger.String("account_id", pm.AccountID))
	return &pm, nil
}

func (r *PostgresBillingRepository) ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.PaymentMethod, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if accountID != "" {
		where = append(where, fmt.Sprintf("account_id = $%d", idx))
		args = append(args, accountID)
		idx++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, status)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM payment_methods"
	q := "SELECT id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, created_at, updated_at, metadata FROM payment_methods"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count payment methods", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.PaymentMethod{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list payment methods", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var methods []*domain.PaymentMethod
	for rows.Next() {
		var pm domain.PaymentMethod
		if err := rows.Scan(&pm.ID, &pm.AccountID, &pm.Type, &pm.Provider, &pm.Last4, &pm.ExpMonth, &pm.ExpYear, &pm.IsDefault, &pm.Status, &pm.CreatedAt, &pm.UpdatedAt, &pm.Metadata); err != nil {
			r.logger.Error("failed to scan payment method row", logger.ErrorField(err))
			return nil, 0, err
		}
		methods = append(methods, &pm)
	}
	return methods, total, nil
}

// --- Refund CRUD ---
func (r *PostgresBillingRepository) CreateRefund(ctx context.Context, refund *domain.Refund) error {
	if refund == nil {
		r.logger.Error("nil refund provided")
		return domain.NewValidationError("refund", "must not be nil")
	}
	if err := refund.Validate(); err != nil {
		r.logger.Error("invalid refund", logger.ErrorField(err), logger.String("payment_id", refund.PaymentID))
		return err
	}
	const q = `INSERT INTO refunds (
		id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
	) ON CONFLICT (id) DO NOTHING`
	_, err := r.db.Exec(ctx, q,
		refund.ID,
		refund.PaymentID,
		refund.InvoiceID,
		refund.Amount,
		refund.Currency,
		refund.Status,
		refund.Reason,
		refund.CreatedAt,
		refund.UpdatedAt,
		refund.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to insert refund", logger.ErrorField(err), logger.String("refund_id", refund.ID), logger.String("payment_id", refund.PaymentID))
		return err
	}
	r.logger.Info("successfully created refund", logger.String("refund_id", refund.ID), logger.String("payment_id", refund.PaymentID))
	return nil
}

func (r *PostgresBillingRepository) UpdateRefund(ctx context.Context, refund *domain.Refund) error {
	if refund == nil {
		r.logger.Error("nil refund provided")
		return domain.NewValidationError("refund", "must not be nil")
	}
	if err := refund.Validate(); err != nil {
		r.logger.Error("invalid refund", logger.ErrorField(err), logger.String("payment_id", refund.PaymentID))
		return err
	}
	const q = `UPDATE refunds SET
		payment_id = $2,
		invoice_id = $3,
		amount = $4,
		currency = $5,
		status = $6,
		reason = $7,
		created_at = $8,
		updated_at = $9,
		metadata = $10
	WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q,
		refund.ID,
		refund.PaymentID,
		refund.InvoiceID,
		refund.Amount,
		refund.Currency,
		refund.Status,
		refund.Reason,
		refund.CreatedAt,
		refund.UpdatedAt,
		refund.Metadata,
	)
	if err != nil {
		r.logger.Error("failed to update refund", logger.ErrorField(err), logger.String("refund_id", refund.ID), logger.String("payment_id", refund.PaymentID))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no refund updated (not found)", logger.String("refund_id", refund.ID), logger.String("payment_id", refund.PaymentID))
		return domain.NewValidationError("refund", "not found")
	}
	r.logger.Info("successfully updated refund", logger.String("refund_id", refund.ID), logger.String("payment_id", refund.PaymentID))
	return nil
}

func (r *PostgresBillingRepository) GetRefundByID(ctx context.Context, id string) (*domain.Refund, error) {
	if id == "" {
		r.logger.Error("empty refund id provided")
		return nil, domain.NewValidationError("refund_id", "must not be empty")
	}
	const q = `SELECT id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata FROM refunds WHERE id = $1`
	row := r.db.QueryRow(ctx, q, id)
	var rfd domain.Refund
	if err := row.Scan(&rfd.ID, &rfd.PaymentID, &rfd.InvoiceID, &rfd.Amount, &rfd.Currency, &rfd.Status, &rfd.Reason, &rfd.CreatedAt, &rfd.UpdatedAt, &rfd.Metadata); err != nil {
		if err == pgx.ErrNoRows {
			r.logger.Warn("refund not found", logger.String("refund_id", id))
			return nil, domain.NewValidationError("refund", "not found")
		}
		r.logger.Error("failed to get refund", logger.ErrorField(err), logger.String("refund_id", id))
		return nil, err
	}
	r.logger.Info("successfully retrieved refund", logger.String("refund_id", rfd.ID), logger.String("payment_id", rfd.PaymentID))
	return &rfd, nil
}

func (r *PostgresBillingRepository) ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]*domain.Refund, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if paymentID != "" {
		where = append(where, fmt.Sprintf("payment_id = $%d", idx))
		args = append(args, paymentID)
		idx++
	}
	if invoiceID != "" {
		where = append(where, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, invoiceID)
		idx++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, status)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM refunds"
	q := "SELECT id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata FROM refunds"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count refunds", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.Refund{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list refunds", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var refunds []*domain.Refund
	for rows.Next() {
		var rfd domain.Refund
		if err := rows.Scan(&rfd.ID, &rfd.PaymentID, &rfd.InvoiceID, &rfd.Amount, &rfd.Currency, &rfd.Status, &rfd.Reason, &rfd.CreatedAt, &rfd.UpdatedAt, &rfd.Metadata); err != nil {
			r.logger.Error("failed to scan refund row", logger.ErrorField(err))
			return nil, 0, err
		}
		refunds = append(refunds, &rfd)
	}
	return refunds, total, nil
}

// --- Credit List ---
func (r *PostgresBillingRepository) ListCredits(ctx context.Context, accountID, invoiceID, status string, page, pageSize int) ([]*domain.Credit, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	where := []string{}
	args := []interface{}{}
	idx := 1
	if accountID != "" {
		where = append(where, fmt.Sprintf("account_id = $%d", idx))
		args = append(args, accountID)
		idx++
	}
	if invoiceID != "" {
		where = append(where, fmt.Sprintf("invoice_id = $%d", idx))
		args = append(args, invoiceID)
		idx++
	}
	if status != "" {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, status)
		idx++
	}
	countQ := "SELECT COUNT(*) FROM credits"
	q := "SELECT id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata FROM credits"
	if len(where) > 0 {
		countQ += " WHERE " + strings.Join(where, " AND ")
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	row := r.db.QueryRow(ctx, countQ, args[:len(args)-2]...)
	var total int
	if err := row.Scan(&total); err != nil {
		r.logger.Error("failed to count credits", logger.ErrorField(err))
		return nil, 0, err
	}
	if total == 0 {
		return []*domain.Credit{}, 0, nil
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		r.logger.Error("failed to list credits", logger.ErrorField(err))
		return nil, 0, err
	}
	defer rows.Close()
	var credits []*domain.Credit
	for rows.Next() {
		var c domain.Credit
		if err := rows.Scan(&c.ID, &c.AccountID, &c.InvoiceID, &c.Amount, &c.Currency, &c.Type, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
			r.logger.Error("failed to scan credit row", logger.ErrorField(err))
			return nil, 0, err
		}
		credits = append(credits, &c)
	}
	return credits, total, nil
}

func (r *PostgresBillingRepository) DeleteBillingPlan(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("empty billing plan id provided")
		return domain.ErrInvalidPlan
	}
	const q = `DELETE FROM billing_plans WHERE id = $1`
	cmd, err := r.db.Exec(ctx, q, id)
	if err != nil {
		r.logger.Error("failed to delete billing plan", logger.ErrorField(err), logger.String("plan_id", id))
		return err
	}
	if cmd.RowsAffected() == 0 {
		r.logger.Warn("no billing plan deleted (not found)", logger.String("plan_id", id))
		return domain.ErrInvalidPlan
	}
	r.logger.Info("successfully deleted billing plan", logger.String("plan_id", id))
	return nil
}
