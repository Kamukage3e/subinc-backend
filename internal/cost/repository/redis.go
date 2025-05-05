package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// RedisCostRepository implements a caching layer for the CostRepository
type RedisCostRepository struct {
	client      *redis.Client
	underlying  CostRepository
	ttl         time.Duration
	logger      *logger.Logger
	ttlStrategy CacheTTLStrategy
}

// NewRedisCostRepository creates a new Redis-backed cost repository cache
func NewRedisCostRepository(client *redis.Client, underlying CostRepository, ttl time.Duration, log *logger.Logger) (CostRepository, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}
	if underlying == nil {
		return nil, fmt.Errorf("underlying repository cannot be nil")
	}
	if ttl == 0 {
		ttl = 1 * time.Hour // Default TTL
	}
	if log == nil {
		log = logger.NewNoop()
	}

	return &RedisCostRepository{
		client:      client,
		underlying:  underlying,
		ttl:         ttl,
		logger:      log,
		ttlStrategy: DefaultCacheTTLStrategy(),
	}, nil
}

// NewRedisCostRepositoryWithOptions creates a new Redis-backed cost repository
// with configurable options
func NewRedisCostRepositoryWithOptions(options RedisRepositoryOptions) (CostRepository, error) {
	if options.Client == nil && options.RedisURL == "" {
		return nil, fmt.Errorf("either Redis client or Redis URL must be provided")
	}

	if options.Underlying == nil {
		return nil, fmt.Errorf("underlying repository cannot be nil")
	}

	if options.TTL == 0 {
		options.TTL = 1 * time.Hour // Default TTL
	}

	if options.Logger == nil {
		options.Logger = logger.NewNoop()
	}

	var client *redis.Client

	// Use provided client or create a new one
	if options.Client != nil {
		client = options.Client
	} else {
		// Create Redis options from URL
		redisOptions, err := redis.ParseURL(options.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
		}

		// Apply connection pool settings
		if options.PoolSize > 0 {
			redisOptions.PoolSize = options.PoolSize
		}

		if options.MinIdleConns > 0 {
			redisOptions.MinIdleConns = options.MinIdleConns
		}

		if options.MaxIdleConns > 0 {
			redisOptions.MaxIdleConns = options.MaxIdleConns
		}

		if options.ConnectTimeout > 0 {
			redisOptions.DialTimeout = options.ConnectTimeout
		}

		if options.ReadTimeout > 0 {
			redisOptions.ReadTimeout = options.ReadTimeout
		}

		if options.WriteTimeout > 0 {
			redisOptions.WriteTimeout = options.WriteTimeout
		}

		// Create the client
		client = redis.NewClient(redisOptions)

		// Verify connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := client.Ping(ctx).Result(); err != nil {
			return nil, fmt.Errorf("failed to connect to Redis: %w", err)
		}
	}

	return &RedisCostRepository{
		client:      client,
		underlying:  options.Underlying,
		ttl:         options.TTL,
		logger:      options.Logger,
		ttlStrategy: options.TTLStrategy,
	}, nil
}

// RedisRepositoryOptions defines configuration options for RedisCostRepository
type RedisRepositoryOptions struct {
	// Client is an existing Redis client to use
	Client *redis.Client

	// RedisURL is a Redis connection URL to use if Client is not provided
	RedisURL string

	// Underlying is the repository implementation to cache
	Underlying CostRepository

	// TTL is the default time-to-live for cached items
	TTL time.Duration

	// Logger is the logger to use
	Logger *logger.Logger

	// Connection pool settings
	PoolSize     int
	MinIdleConns int
	MaxIdleConns int

	// Timeouts
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// TTLStrategy is the strategy for determining TTL for different types of data
	TTLStrategy CacheTTLStrategy
}

// StoreCost stores a cost record and invalidates related caches
func (r *RedisCostRepository) StoreCost(ctx context.Context, cost *domain.Cost) error {
	r.logger.Debug("Storing cost record with caching",
		logger.String("cost_id", cost.ID),
		logger.String("tenant_id", cost.TenantID))

	if err := r.underlying.StoreCost(ctx, cost); err != nil {
		r.logger.Error("Failed to store cost record in underlying repository",
			logger.ErrorField(err),
			logger.String("cost_id", cost.ID))
		return err
	}

	// Invalidate caches
	if err := r.invalidateTenantCaches(ctx, cost.TenantID); err != nil {
		r.logger.Warn("Failed to invalidate tenant caches",
			logger.ErrorField(err),
			logger.String("tenant_id", cost.TenantID))
	}

	r.logger.Debug("Successfully stored cost record and invalidated caches",
		logger.String("cost_id", cost.ID),
		logger.String("tenant_id", cost.TenantID))
	return nil
}

// StoreCosts stores multiple cost records and invalidates related caches
func (r *RedisCostRepository) StoreCosts(ctx context.Context, costs []*domain.Cost) error {
	if len(costs) == 0 {
		r.logger.Debug("No cost records to store, skipping")
		return nil
	}

	r.logger.Debug("Storing multiple cost records with caching",
		logger.Int("count", len(costs)))

	if err := r.underlying.StoreCosts(ctx, costs); err != nil {
		r.logger.Error("Failed to store cost records in underlying repository",
			logger.ErrorField(err),
			logger.Int("count", len(costs)))
		return err
	}

	// Invalidate caches for each tenant
	tenantIDs := map[string]bool{}
	for _, cost := range costs {
		tenantIDs[cost.TenantID] = true
	}

	for tenantID := range tenantIDs {
		if err := r.invalidateTenantCaches(ctx, tenantID); err != nil {
			r.logger.Warn("Failed to invalidate tenant caches",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
		}
	}

	r.logger.Debug("Successfully stored cost records and invalidated caches",
		logger.Int("count", len(costs)),
		logger.Int("tenant_count", len(tenantIDs)))
	return nil
}

// GetCostByID retrieves a cost record by ID with caching
func (r *RedisCostRepository) GetCostByID(ctx context.Context, id string) (*domain.Cost, error) {
	if id == "" {
		r.logger.Error("Invalid cost ID for GetCostByID", logger.String("cost_id", id))
		return nil, domain.ErrInvalidResource
	}

	// Try to get from cache
	cacheKey := fmt.Sprintf("cost:%s", id)
	r.logger.Debug("Checking cache for cost record", logger.String("cache_key", cacheKey))

	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		// Cache hit
		var cost domain.Cost
		if err := json.Unmarshal(data, &cost); err == nil {
			r.logger.Debug("Cache hit for cost record",
				logger.String("cost_id", id),
				logger.String("tenant_id", cost.TenantID))
			return &cost, nil
		}

		r.logger.Warn("Failed to unmarshal cached cost record",
			logger.ErrorField(err),
			logger.String("cost_id", id))

		// Delete the corrupted cache entry
		if delErr := r.client.Del(ctx, cacheKey).Err(); delErr != nil {
			r.logger.Warn("Failed to delete corrupted cache entry",
				logger.ErrorField(delErr),
				logger.String("cost_id", id))
		}
	} else if err != redis.Nil {
		// Real Redis error, not just missing key
		r.logger.Warn("Redis error when retrieving cost record",
			logger.ErrorField(err),
			logger.String("cost_id", id))
	}

	r.logger.Debug("Cache miss for cost record, fetching from underlying repository",
		logger.String("cost_id", id))

	// Get from underlying repository
	cost, err := r.underlying.GetCostByID(ctx, id)
	if err != nil {
		r.logger.Error("Failed to get cost record from underlying repository",
			logger.ErrorField(err),
			logger.String("cost_id", id))
		return nil, err
	}

	// Cache the result
	if cost != nil {
		// Use a context with timeout for cache operations
		cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		data, err := json.Marshal(cost)
		if err == nil {
			r.logger.Debug("Caching cost record",
				logger.String("cost_id", id),
				logger.Duration("ttl", r.ttl))

			// Use SetNX to avoid overwriting newer data
			if err := r.client.SetNX(cacheCtx, cacheKey, data, r.ttl).Err(); err != nil {
				r.logger.Warn("Failed to cache cost record",
					logger.ErrorField(err),
					logger.String("cost_id", id))
			}
		} else {
			r.logger.Warn("Failed to marshal cost record for caching",
				logger.ErrorField(err),
				logger.String("cost_id", id))
		}
	}

	return cost, nil
}

// QueryCosts queries cost records with caching for repeatable queries
func (r *RedisCostRepository) QueryCosts(ctx context.Context, query domain.CostQuery) ([]*domain.Cost, int, error) {
	// Validate input
	if err := query.Validate(); err != nil {
		r.logger.Error("Invalid cost query",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, 0, err
	}

	// Enforce tenant isolation
	if query.TenantID == "" {
		r.logger.Error("Missing tenant ID in cost query")
		return nil, 0, domain.ErrInvalidTenant
	}

	// For complex queries, we'll compute a cache key based on the query parameters
	cacheKey, err := r.queryCacheKey(query)
	if err != nil {
		r.logger.Warn("Failed to generate cache key for query",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		// If we can't compute a cache key, just pass through to underlying
		return r.underlying.QueryCosts(ctx, query)
	}

	r.logger.Debug("Checking cache for cost query results",
		logger.String("cache_key", cacheKey),
		logger.String("tenant_id", query.TenantID),
		logger.Int("page", query.Page),
		logger.Int("page_size", query.PageSize))

	// Use a timeout for cache operations
	cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Try to get from cache
	data, err := r.client.Get(cacheCtx, cacheKey).Bytes()
	if err == nil {
		var result struct {
			Costs    []*domain.Cost `json:"costs"`
			Total    int            `json:"total"`
			CachedAt time.Time      `json:"cached_at"`
		}

		if err := json.Unmarshal(data, &result); err == nil {
			// Check if cache data is stale for time-sensitive queries
			isStale := false

			// If query has a recent time range (e.g., last 24 hours), consider it stale after 5 minutes
			if !query.StartTime.IsZero() && !query.EndTime.IsZero() {
				now := time.Now()
				if query.EndTime.After(now.Add(-24*time.Hour)) &&
					time.Since(result.CachedAt) > 5*time.Minute {
					isStale = true
					r.logger.Debug("Cache hit but data is stale (recent time range)",
						logger.String("tenant_id", query.TenantID),
						logger.Duration("age", time.Since(result.CachedAt)))
				}
			}

			if !isStale {
				r.logger.Debug("Cache hit for cost query",
					logger.String("tenant_id", query.TenantID),
					logger.Int("result_count", len(result.Costs)),
					logger.Int("total_count", result.Total),
					logger.Duration("cached_for", time.Since(result.CachedAt)))
				return result.Costs, result.Total, nil
			}
		} else {
			r.logger.Warn("Failed to unmarshal cached cost query result",
				logger.ErrorField(err),
				logger.String("tenant_id", query.TenantID))

			// Delete the corrupted cache entry
			if delErr := r.client.Del(cacheCtx, cacheKey).Err(); delErr != nil {
				r.logger.Warn("Failed to delete corrupted cache entry",
					logger.ErrorField(delErr),
					logger.String("cache_key", cacheKey))
			}
		}
	} else if err != redis.Nil {
		// Real Redis error, not just missing key
		r.logger.Warn("Redis error when retrieving cost query result",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID),
			logger.String("cache_key", cacheKey))
	} else {
		r.logger.Debug("Cache miss for cost query, fetching from underlying repository",
			logger.String("tenant_id", query.TenantID))
	}

	// Get from underlying repository
	costs, total, err := r.underlying.QueryCosts(ctx, query)
	if err != nil {
		r.logger.Error("Failed to query costs from underlying repository",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, 0, err
	}

	// Cache asynchronously to not block the response
	go func() {
		// Only cache if we have a reasonable result set
		// This prevents huge result sets from overwhelming Redis
		if costs == nil || len(costs) > 2000 {
			if costs == nil {
				r.logger.Debug("Not caching nil results", logger.String("tenant_id", query.TenantID))
			} else {
				r.logger.Debug("Result set too large to cache",
					logger.String("tenant_id", query.TenantID),
					logger.Int("result_count", len(costs)))
			}
			return
		}

		// Use a background context for caching
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer bgCancel()

		result := struct {
			Costs    []*domain.Cost `json:"costs"`
			Total    int            `json:"total"`
			CachedAt time.Time      `json:"cached_at"`
		}{
			Costs:    costs,
			Total:    total,
			CachedAt: time.Now(),
		}

		data, err := json.Marshal(result)
		if err != nil {
			r.logger.Warn("Failed to marshal cost query result for caching",
				logger.ErrorField(err),
				logger.String("tenant_id", query.TenantID))
			return
		}

		// Determine appropriate TTL based on various factors
		ttl := r.determineTTL(query, costs, total)

		r.logger.Debug("Caching cost query result",
			logger.String("tenant_id", query.TenantID),
			logger.String("cache_key", cacheKey),
			logger.Int("result_count", len(costs)),
			logger.Int("total_count", total),
			logger.Duration("ttl", ttl))

		if err := r.client.Set(bgCtx, cacheKey, data, ttl).Err(); err != nil {
			r.logger.Warn("Failed to cache cost query result",
				logger.ErrorField(err),
				logger.String("tenant_id", query.TenantID))
		}
	}()

	r.logger.Debug("Successfully retrieved cost records from underlying repository",
		logger.String("tenant_id", query.TenantID),
		logger.Int("result_count", len(costs)),
		logger.Int("total_count", total))

	return costs, total, nil
}

// determineTTL determines the appropriate TTL for a cost query based on various factors
func (r *RedisCostRepository) determineTTL(query domain.CostQuery, costs []*domain.Cost, total int) time.Duration {
	// Use default strategy if not set
	strategy := r.ttlStrategy
	if strategy.DefaultTTL == 0 {
		strategy = DefaultCacheTTLStrategy()
	}

	// Empty results get a shorter TTL to prevent caching absence for too long
	if len(costs) == 0 || total == 0 {
		return strategy.EmptyResultTTL
	}

	// Check for high cardinality queries
	if isHighCardinalityQuery(query) {
		return min(strategy.QueryTTL, strategy.HighCardinalityMaxTTL)
	}

	// Historical data can be cached longer
	if isHistoricalQuery(query) {
		return strategy.ReadOnlyTTL
	}

	// If query is for current billing period, shorter TTL
	if isCurrentBillingPeriodQuery(query) {
		return strategy.FrequentChangeMaxTTL
	}

	// Default query TTL
	return strategy.QueryTTL
}

// determineForecastTTL determines the TTL for forecast data
func (r *RedisCostRepository) determineForecastTTL(forecast *domain.Forecast) time.Duration {
	// Use default strategy if not set
	strategy := r.ttlStrategy
	if strategy.DefaultTTL == 0 {
		strategy = DefaultCacheTTLStrategy()
	}

	// Forecasts for the future can be cached longer
	now := time.Now()
	if forecast.StartTime.After(now) {
		// The further in the future, the longer we can cache
		daysInFuture := forecast.StartTime.Sub(now).Hours() / 24
		if daysInFuture > 7 {
			return 2 * strategy.ForecastTTL
		}
	}

	// Historical forecasts (with actual data) can be cached longer
	if forecast.EndTime.Before(now) {
		return strategy.ReadOnlyTTL
	}

	return strategy.ForecastTTL
}

// determineSummaryTTL determines the TTL for cost summary data
func (r *RedisCostRepository) determineSummaryTTL(summary *domain.CostSummary) time.Duration {
	// Use default strategy if not set
	strategy := r.ttlStrategy
	if strategy.DefaultTTL == 0 {
		strategy = DefaultCacheTTLStrategy()
	}

	// Historical summaries can be cached longer
	now := time.Now()
	if summary.EndTime.Before(now.AddDate(0, 0, -7)) {
		return strategy.ReadOnlyTTL
	}

	// Current billing period summaries change frequently
	if isCurrentBillingPeriod(summary.StartTime, summary.EndTime) {
		return strategy.FrequentChangeMaxTTL
	}

	return strategy.SummaryTTL
}

// isHighCardinalityQuery checks if a query has high cardinality (many potential results)
func isHighCardinalityQuery(query domain.CostQuery) bool {
	// Check for common high cardinality query patterns
	if len(query.ResourceIDs) > 10 {
		return true
	}

	// Queries without much filtering tend to be high cardinality
	if len(query.Providers) == 0 &&
		len(query.AccountIDs) == 0 &&
		len(query.ResourceTypes) == 0 &&
		len(query.Services) == 0 &&
		len(query.Regions) == 0 {
		return true
	}

	// Queries over large time ranges
	if !query.StartTime.IsZero() && !query.EndTime.IsZero() {
		// More than 3 months
		if query.EndTime.Sub(query.StartTime) > 90*24*time.Hour {
			return true
		}
	}

	return false
}

// isHistoricalQuery checks if a query is for historical data
func isHistoricalQuery(query domain.CostQuery) bool {
	now := time.Now()

	// If end time is more than 7 days in the past, it's historical
	if !query.EndTime.IsZero() && query.EndTime.Before(now.AddDate(0, 0, -7)) {
		return true
	}

	return false
}

// isCurrentBillingPeriodQuery checks if a query is for the current billing period
func isCurrentBillingPeriodQuery(query domain.CostQuery) bool {
	now := time.Now()

	// If time range includes today
	if !query.StartTime.IsZero() && !query.EndTime.IsZero() {
		startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		endOfToday := startOfToday.AddDate(0, 0, 1).Add(-time.Nanosecond)

		// Query range overlaps with today
		if (query.StartTime.Before(endOfToday) || query.StartTime.Equal(endOfToday)) &&
			(query.EndTime.After(startOfToday) || query.EndTime.Equal(startOfToday)) {
			return true
		}
	}

	return false
}

// isCurrentBillingPeriod checks if a date range includes the current billing period
func isCurrentBillingPeriod(start, end time.Time) bool {
	now := time.Now()

	// If time range includes today
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfToday := startOfToday.AddDate(0, 0, 1).Add(-time.Nanosecond)

	// Range overlaps with today
	if (start.Before(endOfToday) || start.Equal(endOfToday)) &&
		(end.After(startOfToday) || end.Equal(startOfToday)) {
		return true
	}

	return false
}

// GetCostSummary gets a cost summary with caching
func (r *RedisCostRepository) GetCostSummary(ctx context.Context, query domain.CostQuery) (*domain.CostSummary, error) {
	// Validate input
	if err := query.Validate(); err != nil {
		r.logger.Error("Invalid cost summary query",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, err
	}

	// Generate a consistent cache key that incorporates all query parameters
	var cacheKeyBuilder strings.Builder
	cacheKeyBuilder.WriteString(fmt.Sprintf("summary:%s:%d:%d",
		query.TenantID,
		query.StartTime.Unix(),
		query.EndTime.Unix()))

	// Add granularity
	if query.Granularity != "" {
		cacheKeyBuilder.WriteString(fmt.Sprintf(":%s", query.Granularity))
	}

	// Add providers
	if len(query.Providers) > 0 {
		providers := make([]string, len(query.Providers))
		for i, p := range query.Providers {
			providers[i] = string(p)
		}
		sort.Strings(providers) // Sort for consistency
		cacheKeyBuilder.WriteString(fmt.Sprintf(":%s", strings.Join(providers, ",")))
	}

	// Add resource types
	if len(query.ResourceTypes) > 0 {
		types := make([]string, len(query.ResourceTypes))
		for i, t := range query.ResourceTypes {
			types[i] = string(t)
		}
		sort.Strings(types) // Sort for consistency
		cacheKeyBuilder.WriteString(fmt.Sprintf(":%s", strings.Join(types, ",")))
	}

	// Add services
	if len(query.Services) > 0 {
		services := make([]string, len(query.Services))
		copy(services, query.Services)
		sort.Strings(services) // Sort for consistency
		cacheKeyBuilder.WriteString(fmt.Sprintf(":%s", strings.Join(services, ",")))
	}

	// Add group by fields
	if len(query.GroupBy) > 0 {
		groupBy := make([]string, len(query.GroupBy))
		copy(groupBy, query.GroupBy)
		sort.Strings(groupBy) // Sort for consistency
		cacheKeyBuilder.WriteString(fmt.Sprintf(":%s", strings.Join(groupBy, ",")))
	}

	cacheKey := cacheKeyBuilder.String()

	r.logger.Debug("Checking cache for cost summary",
		logger.String("cache_key", cacheKey),
		logger.String("tenant_id", query.TenantID))

	// Try to get from cache
	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var summary domain.CostSummary
		if err := json.Unmarshal(data, &summary); err == nil {
			r.logger.Debug("Cache hit for cost summary",
				logger.String("tenant_id", query.TenantID),
				logger.Float64("total_cost", summary.TotalCost))
			return &summary, nil
		}

		r.logger.Warn("Failed to unmarshal cached cost summary",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))

		// Delete the corrupted cache entry
		if delErr := r.client.Del(ctx, cacheKey).Err(); delErr != nil {
			r.logger.Warn("Failed to delete corrupted cache entry",
				logger.ErrorField(delErr),
				logger.String("cache_key", cacheKey))
		}
	} else if err != redis.Nil {
		// Real Redis error, not just missing key
		r.logger.Warn("Redis error when retrieving cost summary",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID),
			logger.String("cache_key", cacheKey))
	}

	r.logger.Debug("Cache miss for cost summary, fetching from underlying repository",
		logger.String("tenant_id", query.TenantID))

	// Get from underlying repository
	summary, err := r.underlying.GetCostSummary(ctx, query)
	if err != nil {
		r.logger.Error("Failed to get cost summary from underlying repository",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return nil, err
	}

	// Cache the result
	if summary != nil {
		// Use a context with timeout for cache operations
		cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()

		data, err := json.Marshal(summary)
		if err == nil {
			r.logger.Debug("Caching cost summary",
				logger.String("tenant_id", query.TenantID),
				logger.String("cache_key", cacheKey),
				logger.Float64("total_cost", summary.TotalCost))

			// Summaries are typically small, so we can use a longer TTL
			summaryTTL := r.determineSummaryTTL(summary)
			if summaryTTL > 24*time.Hour {
				summaryTTL = 24 * time.Hour // Cap at 24 hours
			}

			if err := r.client.Set(cacheCtx, cacheKey, data, summaryTTL).Err(); err != nil {
				r.logger.Warn("Failed to cache cost summary",
					logger.ErrorField(err),
					logger.String("tenant_id", query.TenantID))
			}
		} else {
			r.logger.Warn("Failed to marshal cost summary for caching",
				logger.ErrorField(err),
				logger.String("tenant_id", query.TenantID))
		}
	}

	return summary, nil
}

// CreateCostImport passes through to underlying repository
func (r *RedisCostRepository) CreateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	return r.underlying.CreateCostImport(ctx, costImport)
}

// UpdateCostImport passes through to underlying repository and invalidates cache
func (r *RedisCostRepository) UpdateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	if costImport == nil {
		r.logger.Error("Attempted to update nil cost import")
		return domain.ErrInvalidResource
	}

	r.logger.Debug("Updating cost import with caching",
		logger.String("import_id", costImport.ID),
		logger.String("tenant_id", costImport.TenantID),
		logger.String("status", costImport.Status))

	if err := r.underlying.UpdateCostImport(ctx, costImport); err != nil {
		r.logger.Error("Failed to update cost import in underlying repository",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID))
		return err
	}

	// Invalidate tenant caches as cost data may have changed
	if err := r.invalidateTenantCaches(ctx, costImport.TenantID); err != nil {
		r.logger.Warn("Failed to invalidate tenant caches after import update",
			logger.ErrorField(err),
			logger.String("tenant_id", costImport.TenantID))
	}

	// Also explicitly invalidate the import cache
	cacheKey := fmt.Sprintf("cost_import:%s", costImport.ID)
	if err := r.client.Del(ctx, cacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate cost import cache",
			logger.ErrorField(err),
			logger.String("import_id", costImport.ID))
	}

	r.logger.Debug("Successfully updated cost import and invalidated caches",
		logger.String("import_id", costImport.ID),
		logger.String("tenant_id", costImport.TenantID))
	return nil
}

// GetCostImportByID retrieves a cost import by ID with caching
func (r *RedisCostRepository) GetCostImportByID(ctx context.Context, id string) (*domain.CostImport, error) {
	if id == "" {
		r.logger.Error("Invalid import ID for GetCostImportByID", logger.String("import_id", id))
		return nil, domain.ErrInvalidResource
	}

	// Try to get from cache
	cacheKey := fmt.Sprintf("cost_import:%s", id)
	r.logger.Debug("Checking cache for cost import", logger.String("cache_key", cacheKey))

	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var costImport domain.CostImport
		if err := json.Unmarshal(data, &costImport); err == nil {
			r.logger.Debug("Cache hit for cost import",
				logger.String("import_id", id),
				logger.String("tenant_id", costImport.TenantID))
			return &costImport, nil
		}
		r.logger.Warn("Failed to unmarshal cached cost import",
			logger.ErrorField(err),
			logger.String("import_id", id))
	} else if err != redis.Nil {
		r.logger.Warn("Redis error when retrieving cost import",
			logger.ErrorField(err),
			logger.String("import_id", id))
	}

	r.logger.Debug("Cache miss for cost import, fetching from underlying repository",
		logger.String("import_id", id))

	// Get from underlying repository
	costImport, err := r.underlying.GetCostImportByID(ctx, id)
	if err != nil {
		r.logger.Error("Failed to get cost import from underlying repository",
			logger.ErrorField(err),
			logger.String("import_id", id))
		return nil, err
	}

	// Cache the result
	if costImport != nil {
		data, err := json.Marshal(costImport)
		if err == nil {
			r.logger.Debug("Caching cost import",
				logger.String("import_id", id),
				logger.Duration("ttl", r.ttl))
			if err := r.client.Set(ctx, cacheKey, data, r.ttl).Err(); err != nil {
				r.logger.Warn("Failed to cache cost import",
					logger.ErrorField(err),
					logger.String("import_id", id))
			}
		} else {
			r.logger.Warn("Failed to marshal cost import for caching",
				logger.ErrorField(err),
				logger.String("import_id", id))
		}
	}

	return costImport, nil
}

// ListCostImports lists cost imports with caching
func (r *RedisCostRepository) ListCostImports(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, page, pageSize int) ([]*domain.CostImport, int, error) {
	cacheKey := fmt.Sprintf("imports:%s:%s:%d:%d:%d:%d", tenantID, provider, startTime.Unix(), endTime.Unix(), page, pageSize)

	// Try to get from cache
	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var result struct {
			Imports []*domain.CostImport
			Total   int
		}
		if err := json.Unmarshal(data, &result); err == nil {
			return result.Imports, result.Total, nil
		}
	}

	// Get from underlying repository
	imports, total, err := r.underlying.ListCostImports(ctx, tenantID, provider, startTime, endTime, page, pageSize)
	if err != nil {
		return nil, 0, err
	}

	// Cache the result
	if imports != nil {
		result := struct {
			Imports []*domain.CostImport
			Total   int
		}{
			Imports: imports,
			Total:   total,
		}
		data, err := json.Marshal(result)
		if err == nil {
			r.client.Set(ctx, cacheKey, data, r.ttl)
		}
	}

	return imports, total, nil
}

// CreateBudget creates a budget record and invalidates related caches
func (r *RedisCostRepository) CreateBudget(ctx context.Context, budget *domain.Budget) error {
	if budget == nil {
		r.logger.Error("Attempted to create nil budget")
		return domain.ErrInvalidResource
	}

	// Validate required fields
	if budget.TenantID == "" {
		r.logger.Error("Budget missing tenant ID")
		return domain.ErrInvalidTenant
	}

	if budget.ID == "" {
		r.logger.Error("Budget missing ID")
		return domain.NewValidationError("id", "must not be empty")
	}

	r.logger.Debug("Creating budget with caching",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID),
		logger.String("name", budget.Name),
		logger.Float64("amount", budget.Amount),
		logger.String("currency", budget.Currency))

	// Forward to underlying repository
	err := r.underlying.CreateBudget(ctx, budget)
	if err != nil {
		r.logger.Error("Failed to create budget in underlying repository",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID),
			logger.String("tenant_id", budget.TenantID))
		return err
	}

	// Create a context with timeout for cache operations
	cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Invalidate budgets list cache
	budgetListKeys := []string{
		fmt.Sprintf("budgets:%s", budget.TenantID),
		fmt.Sprintf("budgets:%s:%s:*", budget.TenantID, budget.Provider),
	}

	for _, key := range budgetListKeys {
		if err := r.client.Del(cacheCtx, key).Err(); err != nil && err != redis.Nil {
			r.logger.Warn("Failed to invalidate budget list cache",
				logger.ErrorField(err),
				logger.String("cache_key", key),
				logger.String("tenant_id", budget.TenantID))
		}
	}

	// Also invalidate by pattern to catch any filtered list queries
	patterns := []string{
		fmt.Sprintf("budgets:%s:*", budget.TenantID),
	}

	// Don't block the main flow for pattern-based invalidation
	go func() {
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer bgCancel()

		for _, pattern := range patterns {
			if err := r.invalidateByPattern(bgCtx, pattern); err != nil {
				r.logger.Warn("Failed to invalidate budget list caches by pattern",
					logger.ErrorField(err),
					logger.String("pattern", pattern),
					logger.String("tenant_id", budget.TenantID))
			}
		}
	}()

	r.logger.Info("Successfully created budget and invalidated caches",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID),
		logger.String("name", budget.Name),
		logger.Float64("amount", budget.Amount))

	return nil
}

// UpdateBudget passes through to underlying repository and invalidates cache
func (r *RedisCostRepository) UpdateBudget(ctx context.Context, budget *domain.Budget) error {
	if budget == nil {
		r.logger.Error("Attempted to update nil budget")
		return domain.ErrInvalidResource
	}

	r.logger.Debug("Updating budget with caching",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID),
		logger.String("name", budget.Name))

	err := r.underlying.UpdateBudget(ctx, budget)
	if err != nil {
		r.logger.Error("Failed to update budget in underlying repository",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID))
		return err
	}

	// Invalidate budget caches
	cacheKey := fmt.Sprintf("budget:%s", budget.ID)
	if err := r.client.Del(ctx, cacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate budget cache",
			logger.ErrorField(err),
			logger.String("budget_id", budget.ID))
	}

	listCacheKey := fmt.Sprintf("budgets:%s", budget.TenantID)
	if err := r.client.Del(ctx, listCacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate budgets list cache",
			logger.ErrorField(err),
			logger.String("tenant_id", budget.TenantID))
	}

	// Also invalidate by pattern to catch any filtered list queries
	pattern := fmt.Sprintf("budgets:%s:*", budget.TenantID)
	if err := r.invalidateByPattern(ctx, pattern); err != nil {
		r.logger.Warn("Failed to invalidate filtered budget list caches",
			logger.ErrorField(err),
			logger.String("tenant_id", budget.TenantID))
	}

	r.logger.Debug("Successfully updated budget and invalidated caches",
		logger.String("budget_id", budget.ID),
		logger.String("tenant_id", budget.TenantID))

	return nil
}

// DeleteBudget passes through to underlying repository and invalidates cache
func (r *RedisCostRepository) DeleteBudget(ctx context.Context, id string) error {
	if id == "" {
		r.logger.Error("Invalid budget ID for DeleteBudget")
		return domain.ErrInvalidResource
	}

	r.logger.Debug("Deleting budget with caching", logger.String("budget_id", id))

	// First get the budget to know its tenant
	budget, err := r.GetBudgetByID(ctx, id)
	if err != nil {
		r.logger.Error("Failed to get budget for deletion",
			logger.ErrorField(err),
			logger.String("budget_id", id))
		return err
	}

	tenantID := ""
	if budget != nil {
		tenantID = budget.TenantID
		r.logger.Debug("Found budget to delete",
			logger.String("budget_id", id),
			logger.String("tenant_id", tenantID))
	}

	err = r.underlying.DeleteBudget(ctx, id)
	if err != nil {
		r.logger.Error("Failed to delete budget from underlying repository",
			logger.ErrorField(err),
			logger.String("budget_id", id))
		return err
	}

	// Invalidate budget caches
	cacheKey := fmt.Sprintf("budget:%s", id)
	if err := r.client.Del(ctx, cacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate budget cache after deletion",
			logger.ErrorField(err),
			logger.String("budget_id", id))
	}

	// If we have the tenant ID, invalidate tenant-specific caches
	if tenantID != "" {
		listCacheKey := fmt.Sprintf("budgets:%s", tenantID)
		if err := r.client.Del(ctx, listCacheKey).Err(); err != nil {
			r.logger.Warn("Failed to invalidate budgets list cache after deletion",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
		}

		// Also invalidate by pattern to catch any filtered list queries
		pattern := fmt.Sprintf("budgets:%s:*", tenantID)
		if err := r.invalidateByPattern(ctx, pattern); err != nil {
			r.logger.Warn("Failed to invalidate filtered budget list caches",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
		}
	}

	r.logger.Debug("Successfully deleted budget and invalidated caches",
		logger.String("budget_id", id),
		logger.String("tenant_id", tenantID))

	return nil
}

// GetBudgetByID retrieves a budget by ID with caching
func (r *RedisCostRepository) GetBudgetByID(ctx context.Context, id string) (*domain.Budget, error) {
	if id == "" {
		return nil, domain.ErrInvalidResource
	}

	// Try to get from cache
	cacheKey := fmt.Sprintf("budget:%s", id)
	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var budget domain.Budget
		if err := json.Unmarshal(data, &budget); err == nil {
			return &budget, nil
		}
	}

	// Get from underlying repository
	budget, err := r.underlying.GetBudgetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if budget != nil {
		data, err := json.Marshal(budget)
		if err == nil {
			r.client.Set(ctx, cacheKey, data, r.ttl)
		}
	}

	return budget, nil
}

// ListBudgets lists budgets with caching
func (r *RedisCostRepository) ListBudgets(ctx context.Context, tenantID string, provider domain.CloudProvider, active bool, page, pageSize int) ([]*domain.Budget, int, error) {
	cacheKey := fmt.Sprintf("budgets:%s:%s:%t:%d:%d", tenantID, provider, active, page, pageSize)

	// Try to get from cache
	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var result struct {
			Budgets []*domain.Budget
			Total   int
		}
		if err := json.Unmarshal(data, &result); err == nil {
			return result.Budgets, result.Total, nil
		}
	}

	// Get from underlying repository
	budgets, total, err := r.underlying.ListBudgets(ctx, tenantID, provider, active, page, pageSize)
	if err != nil {
		return nil, 0, err
	}

	// Cache the result
	if budgets != nil {
		result := struct {
			Budgets []*domain.Budget
			Total   int
		}{
			Budgets: budgets,
			Total:   total,
		}
		data, err := json.Marshal(result)
		if err == nil {
			r.client.Set(ctx, cacheKey, data, r.ttl)
		}
	}

	return budgets, total, nil
}

// CreateAnomaly passes through to underlying repository
func (r *RedisCostRepository) CreateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	err := r.underlying.CreateAnomaly(ctx, anomaly)
	if err != nil {
		return err
	}

	// Invalidate anomaly caches
	cacheKey := fmt.Sprintf("anomalies:%s", anomaly.TenantID)
	r.client.Del(ctx, cacheKey)

	return nil
}

// UpdateAnomaly passes through to underlying repository and invalidates cache
func (r *RedisCostRepository) UpdateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	if anomaly == nil {
		r.logger.Error("Attempted to update nil anomaly")
		return domain.ErrInvalidResource
	}

	r.logger.Debug("Updating anomaly with caching",
		logger.String("anomaly_id", anomaly.ID),
		logger.String("tenant_id", anomaly.TenantID),
		logger.String("status", anomaly.Status))

	err := r.underlying.UpdateAnomaly(ctx, anomaly)
	if err != nil {
		r.logger.Error("Failed to update anomaly in underlying repository",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID))
		return err
	}

	// Invalidate anomaly caches
	cacheKey := fmt.Sprintf("anomaly:%s", anomaly.ID)
	if err := r.client.Del(ctx, cacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate anomaly cache",
			logger.ErrorField(err),
			logger.String("anomaly_id", anomaly.ID))
	}

	listCacheKey := fmt.Sprintf("anomalies:%s", anomaly.TenantID)
	if err := r.client.Del(ctx, listCacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate anomalies list cache",
			logger.ErrorField(err),
			logger.String("tenant_id", anomaly.TenantID))
	}

	// Also invalidate by pattern to catch any time-range or status-based list queries
	pattern := fmt.Sprintf("anomalies:%s:*", anomaly.TenantID)
	if err := r.invalidateByPattern(ctx, pattern); err != nil {
		r.logger.Warn("Failed to invalidate filtered anomaly list caches",
			logger.ErrorField(err),
			logger.String("tenant_id", anomaly.TenantID))
	}

	r.logger.Debug("Successfully updated anomaly and invalidated caches",
		logger.String("anomaly_id", anomaly.ID),
		logger.String("tenant_id", anomaly.TenantID),
		logger.String("status", anomaly.Status))

	return nil
}

// GetAnomalyByID retrieves an anomaly by ID with caching
func (r *RedisCostRepository) GetAnomalyByID(ctx context.Context, id string) (*domain.Anomaly, error) {
	if id == "" {
		return nil, domain.ErrInvalidResource
	}

	// Try to get from cache
	cacheKey := fmt.Sprintf("anomaly:%s", id)
	data, err := r.client.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var anomaly domain.Anomaly
		if err := json.Unmarshal(data, &anomaly); err == nil {
			return &anomaly, nil
		}
	}

	// Get from underlying repository
	anomaly, err := r.underlying.GetAnomalyByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if anomaly != nil {
		data, err := json.Marshal(anomaly)
		if err == nil {
			r.client.Set(ctx, cacheKey, data, r.ttl)
		}
	}

	return anomaly, nil
}

// ListAnomalies lists anomalies with caching
func (r *RedisCostRepository) ListAnomalies(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, status string, page, pageSize int) ([]*domain.Anomaly, int, error) {
	// Validate inputs
	if tenantID == "" {
		r.logger.Error("Missing tenant ID for ListAnomalies")
		return nil, 0, domain.ErrInvalidTenant
	}

	// Enforce reasonable pagination limits
	if page < 1 {
		page = 1
	}

	if pageSize < 1 || pageSize > 100 {
		pageSize = 100
	}

	// Create a deterministic cache key
	var keyBuilder strings.Builder
	keyBuilder.WriteString(fmt.Sprintf("anomalies:%s", tenantID))

	if provider != "" {
		keyBuilder.WriteString(fmt.Sprintf(":%s", provider))
	} else {
		keyBuilder.WriteString(":*") // wildcard for provider
	}

	if !startTime.IsZero() {
		keyBuilder.WriteString(fmt.Sprintf(":%d", startTime.Unix()))
	} else {
		keyBuilder.WriteString(":0") // no start time
	}

	if !endTime.IsZero() {
		keyBuilder.WriteString(fmt.Sprintf(":%d", endTime.Unix()))
	} else {
		keyBuilder.WriteString(":0") // no end time
	}

	if status != "" {
		keyBuilder.WriteString(fmt.Sprintf(":%s", status))
	} else {
		keyBuilder.WriteString(":*") // wildcard for status
	}

	keyBuilder.WriteString(fmt.Sprintf(":%d:%d", page, pageSize))

	cacheKey := keyBuilder.String()

	r.logger.Debug("Checking cache for anomalies list",
		logger.String("cache_key", cacheKey),
		logger.String("tenant_id", tenantID),
		logger.Int("page", page),
		logger.Int("page_size", pageSize))

	// Use a context with timeout for cache operations
	cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Try to get from cache
	data, err := r.client.Get(cacheCtx, cacheKey).Bytes()
	if err == nil {
		var result struct {
			Anomalies []*domain.Anomaly `json:"anomalies"`
			Total     int               `json:"total"`
		}

		if err := json.Unmarshal(data, &result); err == nil {
			r.logger.Debug("Cache hit for anomalies list",
				logger.String("tenant_id", tenantID),
				logger.Int("result_count", len(result.Anomalies)),
				logger.Int("total_count", result.Total))
			return result.Anomalies, result.Total, nil
		}

		r.logger.Warn("Failed to unmarshal cached anomalies list",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey))

		// Delete corrupted cache entry
		if delErr := r.client.Del(cacheCtx, cacheKey).Err(); delErr != nil {
			r.logger.Warn("Failed to delete corrupted cache entry",
				logger.ErrorField(delErr),
				logger.String("cache_key", cacheKey))
		}
	} else if err != redis.Nil {
		// Real Redis error, not just missing key
		r.logger.Warn("Redis error when retrieving anomalies list",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey))
	} else {
		r.logger.Debug("Cache miss for anomalies list",
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey))
	}

	// Get from underlying repository
	anomalies, total, err := r.underlying.ListAnomalies(ctx, tenantID, provider, startTime, endTime, status, page, pageSize)
	if err != nil {
		r.logger.Error("Failed to list anomalies from underlying repository",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, 0, err
	}

	// Don't block the main flow for caching, but do it in background
	go func() {
		if len(anomalies) == 0 {
			// Don't cache empty results for too long
			if total == 0 {
				cacheEmptyResults(tenantID, cacheKey, r.client, r.logger)
			}
			return
		}

		// Use a background context for caching
		bgCtx, bgCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer bgCancel()

		result := struct {
			Anomalies []*domain.Anomaly `json:"anomalies"`
			Total     int               `json:"total"`
		}{
			Anomalies: anomalies,
			Total:     total,
		}

		data, err := json.Marshal(result)
		if err != nil {
			r.logger.Warn("Failed to marshal anomalies list for caching",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
			return
		}

		// Determine TTL based on result recency and size
		ttl := r.ttl

		// Use shorter TTL for recently detected anomalies to ensure freshness
		hasRecentAnomalies := false
		for _, a := range anomalies {
			if time.Since(a.DetectedAt) < 12*time.Hour {
				hasRecentAnomalies = true
				break
			}
		}

		if hasRecentAnomalies {
			ttl = 15 * time.Minute // Short TTL for recent anomalies
		} else if len(anomalies) > 50 {
			ttl = r.ttl / 2 // Shorter TTL for large result sets
		}

		r.logger.Debug("Caching anomalies list result",
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey),
			logger.Int("result_count", len(anomalies)),
			logger.Int("total_count", total),
			logger.Duration("ttl", ttl))

		if err := r.client.Set(bgCtx, cacheKey, data, ttl).Err(); err != nil {
			r.logger.Warn("Failed to cache anomalies list",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID),
				logger.String("cache_key", cacheKey))
		}
	}()

	r.logger.Debug("Successfully retrieved anomalies",
		logger.String("tenant_id", tenantID),
		logger.Int("result_count", len(anomalies)),
		logger.Int("total_count", total))

	return anomalies, total, nil
}

// cacheEmptyResults is a helper function to cache empty results with a short TTL
func cacheEmptyResults(tenantID, cacheKey string, client *redis.Client, log *logger.Logger) {
	bgCtx, bgCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer bgCancel()

	emptyResult := struct {
		Anomalies []*domain.Anomaly `json:"anomalies"`
		Total     int               `json:"total"`
	}{
		Anomalies: []*domain.Anomaly{},
		Total:     0,
	}

	data, err := json.Marshal(emptyResult)
	if err != nil {
		log.Warn("Failed to marshal empty result for caching",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return
	}

	// Short TTL for empty results to avoid false negatives for too long
	shortTTL := 5 * time.Minute

	if err := client.Set(bgCtx, cacheKey, data, shortTTL).Err(); err != nil {
		log.Warn("Failed to cache empty result",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey))
	}
}

// StoreForecast stores a forecast and invalidates related caches
func (r *RedisCostRepository) StoreForecast(ctx context.Context, forecast *domain.Forecast) error {
	if forecast == nil {
		r.logger.Error("Attempted to store nil forecast")
		return domain.ErrInvalidResource
	}

	r.logger.Debug("Storing forecast with caching",
		logger.String("forecast_id", forecast.ID),
		logger.String("tenant_id", forecast.TenantID))

	if err := r.underlying.StoreForecast(ctx, forecast); err != nil {
		r.logger.Error("Failed to store forecast in underlying repository",
			logger.ErrorField(err),
			logger.String("forecast_id", forecast.ID))
		return err
	}

	// Invalidate forecast caches
	cacheKey := fmt.Sprintf("forecast:%s:%s:%s", forecast.TenantID, forecast.Provider, forecast.AccountID)
	if err := r.client.Del(ctx, cacheKey).Err(); err != nil {
		r.logger.Warn("Failed to invalidate forecast cache",
			logger.ErrorField(err),
			logger.String("forecast_id", forecast.ID))
	}

	// Also invalidate by pattern to catch time-range based keys
	pattern := fmt.Sprintf("forecast:%s:%s:%s:*", forecast.TenantID, forecast.Provider, forecast.AccountID)
	if err := r.invalidateByPattern(ctx, pattern); err != nil {
		r.logger.Warn("Failed to invalidate time-based forecast caches",
			logger.ErrorField(err),
			logger.String("tenant_id", forecast.TenantID))
	}

	r.logger.Debug("Successfully stored forecast and invalidated caches",
		logger.String("forecast_id", forecast.ID),
		logger.String("tenant_id", forecast.TenantID))
	return nil
}

// GetForecast retrieves a forecast with caching
func (r *RedisCostRepository) GetForecast(ctx context.Context, tenantID string, provider domain.CloudProvider, accountID string, startTime, endTime time.Time) (*domain.Forecast, error) {
	if tenantID == "" {
		r.logger.Error("Invalid tenant ID for GetForecast")
		return nil, domain.ErrInvalidTenant
	}

	// Create a unique cache key based on all parameters
	cacheKey := fmt.Sprintf("forecast:%s:%s:%s:%d:%d", tenantID, provider, accountID, startTime.Unix(), endTime.Unix())
	r.logger.Debug("Checking cache for forecast",
		logger.String("cache_key", cacheKey),
		logger.String("tenant_id", tenantID))

	// Use a context with timeout specifically for the cache operations
	cacheCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Try to get from cache
	data, err := r.client.Get(cacheCtx, cacheKey).Bytes()
	if err == nil {
		var forecast domain.Forecast
		if err := json.Unmarshal(data, &forecast); err == nil {
			r.logger.Debug("Cache hit for forecast",
				logger.String("forecast_id", forecast.ID),
				logger.String("tenant_id", tenantID))
			return &forecast, nil
		}
		r.logger.Warn("Failed to unmarshal cached forecast",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))

		// Delete the corrupted cache entry, but don't block the main flow if this fails
		go func() {
			delCtx, delCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer delCancel()
			if delErr := r.client.Del(delCtx, cacheKey).Err(); delErr != nil {
				r.logger.Warn("Failed to delete corrupted forecast cache entry",
					logger.ErrorField(delErr),
					logger.String("cache_key", cacheKey))
			}
		}()
	} else if err != redis.Nil {
		r.logger.Warn("Redis error when retrieving forecast",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID),
			logger.String("cache_key", cacheKey))
	}

	r.logger.Debug("Cache miss for forecast, fetching from underlying repository",
		logger.String("tenant_id", tenantID),
		logger.String("provider", string(provider)),
		logger.String("account_id", accountID))

	// Get from underlying repository using the original context
	forecast, err := r.underlying.GetForecast(ctx, tenantID, provider, accountID, startTime, endTime)
	if err != nil {
		if err == domain.ErrForecastNotFound {
			r.logger.Debug("Forecast not found in underlying repository",
				logger.String("tenant_id", tenantID),
				logger.String("provider", string(provider)))
		} else {
			r.logger.Error("Failed to get forecast from underlying repository",
				logger.ErrorField(err),
				logger.String("tenant_id", tenantID))
		}
		return nil, err
	}

	// Cache the result, but don't block if Redis is slow
	if forecast != nil {
		go func() {
			cacheWriteCtx, cacheWriteCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cacheWriteCancel()

			data, err := json.Marshal(forecast)
			if err != nil {
				r.logger.Warn("Failed to marshal forecast for caching",
					logger.ErrorField(err),
					logger.String("forecast_id", forecast.ID))
				return
			}

			// Determine TTL based on time range - shorter TTL for forecasts closer to now
			ttl := r.determineForecastTTL(forecast)

			r.logger.Debug("Caching forecast",
				logger.String("forecast_id", forecast.ID),
				logger.Duration("ttl", ttl))

			if err := r.client.Set(cacheWriteCtx, cacheKey, data, ttl).Err(); err != nil {
				r.logger.Warn("Failed to cache forecast",
					logger.ErrorField(err),
					logger.String("forecast_id", forecast.ID))
			}
		}()
	}

	return forecast, nil
}

// HealthCheck performs a connectivity check on the Redis repository
func (r *RedisCostRepository) HealthCheck(ctx context.Context) error {
	// Create a deadline for the health check
	ctxTimeout, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Try to PING Redis
	status := r.client.Ping(ctxTimeout)
	result, err := status.Result()

	if err != nil {
		r.logger.Error("Redis health check failed",
			logger.ErrorField(err))
		return fmt.Errorf("redis health check failed: %w", err)
	}

	if result != "PONG" {
		r.logger.Error("Redis health check returned unexpected result",
			logger.String("result", result))
		return fmt.Errorf("redis health check returned unexpected result: %s", result)
	}

	// If we also need to check the underlying repository
	if checkUnderlying, ok := r.underlying.(interface{ HealthCheck(context.Context) error }); ok {
		if err := checkUnderlying.HealthCheck(ctx); err != nil {
			r.logger.Error("Underlying repository health check failed",
				logger.ErrorField(err))
			return fmt.Errorf("underlying repository health check failed: %w", err)
		}
	}

	r.logger.Debug("Redis health check passed")
	return nil
}

// Helper methods

// invalidateTenantCaches invalidates all caches for a tenant
func (r *RedisCostRepository) invalidateTenantCaches(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		r.logger.Error("Empty tenant ID provided for cache invalidation")
		return domain.ErrInvalidTenant
	}

	r.logger.Debug("Starting tenant cache invalidation",
		logger.String("tenant_id", tenantID))

	// First try to invalidate by known patterns for better performance
	patterns := []string{
		fmt.Sprintf("cost:*:%s:*", tenantID),
		fmt.Sprintf("query:*%s*", tenantID),
		fmt.Sprintf("summary:%s:*", tenantID),
		fmt.Sprintf("budget:%s:*", tenantID),
		fmt.Sprintf("budgets:%s:*", tenantID),
		fmt.Sprintf("anomaly:%s:*", tenantID),
		fmt.Sprintf("anomalies:%s:*", tenantID),
		fmt.Sprintf("forecast:%s:*", tenantID),
		fmt.Sprintf("imports:%s:*", tenantID),
		fmt.Sprintf("cost_import:%s*", tenantID),
	}

	var totalInvalidated int64
	var invalidationErrors, scanErrors int

	// Use a more generic pattern as a fallback
	for _, pattern := range patterns {
		var cursor uint64
		var batchSize int64 = 100

		for {
			// SCAN with COUNT option for better performance
			keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, batchSize).Result()
			if err != nil {
				scanErrors++
				r.logger.Error("Error scanning for tenant cache keys",
					logger.ErrorField(err),
					logger.String("tenant_id", tenantID),
					logger.String("pattern", pattern))

				// Continue with next pattern if we encounter issues
				if scanErrors > 5 {
					r.logger.Error("Too many scan errors, skipping pattern",
						logger.String("pattern", pattern),
						logger.String("tenant_id", tenantID))
					break
				}

				// Continue with next cursor
				cursor = nextCursor
				continue
			}

			if len(keys) > 0 {
				r.logger.Debug("Found tenant cache keys to delete",
					logger.String("tenant_id", tenantID),
					logger.String("pattern", pattern),
					logger.Int("batch_size", len(keys)))

				// Delete in batches
				if err := r.client.Del(ctx, keys...).Err(); err != nil {
					invalidationErrors++
					r.logger.Error("Failed to delete tenant cache keys",
						logger.ErrorField(err),
						logger.String("tenant_id", tenantID),
						logger.String("pattern", pattern),
						logger.Int("key_count", len(keys)))
				} else {
					totalInvalidated += int64(len(keys))
				}
			}

			// Exit the loop when we've processed all keys
			if nextCursor == 0 {
				break
			}
			cursor = nextCursor
		}
	}

	// Fall back to a more generic pattern if we haven't found many keys
	if totalInvalidated < 10 {
		// Using a very generic pattern as a last resort
		pattern := fmt.Sprintf("*%s*", tenantID)
		r.logger.Debug("Using generic fallback pattern for tenant cache",
			logger.String("tenant_id", tenantID),
			logger.String("pattern", pattern))

		var cursor uint64
		var batchSize int64 = 100

		for {
			keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, batchSize).Result()
			if err != nil {
				r.logger.Error("Error scanning with fallback pattern",
					logger.ErrorField(err),
					logger.String("tenant_id", tenantID))
				break
			}

			if len(keys) > 0 {
				if err := r.client.Del(ctx, keys...).Err(); err != nil {
					r.logger.Error("Failed to delete keys with fallback pattern",
						logger.ErrorField(err),
						logger.String("tenant_id", tenantID),
						logger.Int("key_count", len(keys)))
				} else {
					totalInvalidated += int64(len(keys))
				}
			}

			if nextCursor == 0 {
				break
			}
			cursor = nextCursor
		}
	}

	if invalidationErrors > 0 || scanErrors > 0 {
		r.logger.Warn("Completed tenant cache invalidation with some errors",
			logger.String("tenant_id", tenantID),
			logger.Int("total_keys_invalidated", int(totalInvalidated)),
			logger.Int("scan_errors", scanErrors),
			logger.Int("invalidation_errors", invalidationErrors))
	} else {
		r.logger.Info("Successfully invalidated tenant caches",
			logger.String("tenant_id", tenantID),
			logger.Int("total_keys_invalidated", int(totalInvalidated)))
	}

	return nil
}

// queryCacheKey generates a cache key for a cost query
func (r *RedisCostRepository) queryCacheKey(query domain.CostQuery) (string, error) {
	if query.TenantID == "" {
		r.logger.Error("Cannot generate cache key for query with empty tenant ID")
		return "", domain.ErrInvalidTenant
	}

	// Create a simplified version of the query for consistent cache keys
	cacheableQuery := struct {
		TenantID      string                 `json:"tenant_id"`
		Providers     []domain.CloudProvider `json:"providers,omitempty"`
		AccountIDs    []string               `json:"account_ids,omitempty"`
		ResourceIDs   []string               `json:"resource_ids,omitempty"`
		ResourceTypes []domain.ResourceType  `json:"resource_types,omitempty"`
		Services      []string               `json:"services,omitempty"`
		Regions       []string               `json:"regions,omitempty"`
		StartTime     int64                  `json:"start_time"`
		EndTime       int64                  `json:"end_time"`
		Granularity   domain.CostGranularity `json:"granularity"`
		GroupBy       []string               `json:"group_by,omitempty"`
		Page          int                    `json:"page,omitempty"`
		PageSize      int                    `json:"page_size,omitempty"`
		SortBy        string                 `json:"sort_by,omitempty"`
		SortDirection string                 `json:"sort_direction,omitempty"`
	}{
		TenantID:      query.TenantID,
		Providers:     query.Providers,
		AccountIDs:    query.AccountIDs,
		ResourceIDs:   query.ResourceIDs,
		ResourceTypes: query.ResourceTypes,
		Services:      query.Services,
		Regions:       query.Regions,
		Granularity:   query.Granularity,
		GroupBy:       query.GroupBy,
		Page:          query.Page,
		PageSize:      query.PageSize,
		SortBy:        query.SortBy,
		SortDirection: query.SortDirection,
	}

	// Convert timestamps to Unix to ensure consistent caching regardless of time zone
	if !query.StartTime.IsZero() {
		cacheableQuery.StartTime = query.StartTime.Unix()
	}
	if !query.EndTime.IsZero() {
		cacheableQuery.EndTime = query.EndTime.Unix()
	}

	// Sort arrays for consistency
	if len(cacheableQuery.Providers) > 0 {
		sort.Slice(cacheableQuery.Providers, func(i, j int) bool {
			return string(cacheableQuery.Providers[i]) < string(cacheableQuery.Providers[j])
		})
	}
	if len(cacheableQuery.AccountIDs) > 0 {
		sort.Strings(cacheableQuery.AccountIDs)
	}
	if len(cacheableQuery.ResourceIDs) > 0 {
		sort.Strings(cacheableQuery.ResourceIDs)
	}
	if len(cacheableQuery.ResourceTypes) > 0 {
		sort.Slice(cacheableQuery.ResourceTypes, func(i, j int) bool {
			return string(cacheableQuery.ResourceTypes[i]) < string(cacheableQuery.ResourceTypes[j])
		})
	}
	if len(cacheableQuery.Services) > 0 {
		sort.Strings(cacheableQuery.Services)
	}
	if len(cacheableQuery.Regions) > 0 {
		sort.Strings(cacheableQuery.Regions)
	}
	if len(cacheableQuery.GroupBy) > 0 {
		sort.Strings(cacheableQuery.GroupBy)
	}

	// Now we can marshal to JSON for a consistent string representation
	data, err := json.Marshal(cacheableQuery)
	if err != nil {
		r.logger.Error("Failed to marshal query for cache key generation",
			logger.ErrorField(err),
			logger.String("tenant_id", query.TenantID))
		return "", fmt.Errorf("failed to marshal query for cache key: %w", err)
	}

	// Add a prefix and use a secure hash to avoid injection attacks or key length limitations
	h := sha256.New()
	h.Write(data)
	key := fmt.Sprintf("query:%s:%x", query.TenantID, h.Sum(nil))

	r.logger.Debug("Generated cache key for query",
		logger.String("tenant_id", query.TenantID),
		logger.String("cache_key", key))

	return key, nil
}

// invalidateByPattern invalidates cache entries matching a pattern
func (r *RedisCostRepository) invalidateByPattern(ctx context.Context, pattern string) error {
	if pattern == "" {
		r.logger.Warn("Empty pattern provided for cache invalidation")
		return fmt.Errorf("empty pattern provided for cache invalidation")
	}

	// Use a timeout to prevent long-running operations
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	r.logger.Debug("Scanning cache keys with pattern", logger.String("pattern", pattern))

	// Use SCAN to efficiently find keys matching the pattern
	iter := r.client.Scan(timeoutCtx, 0, pattern, 100).Iterator()

	var keysToDelete []string
	keysScanned := 0

	for iter.Next(timeoutCtx) {
		key := iter.Val()
		keysToDelete = append(keysToDelete, key)
		keysScanned++

		// Delete in batches of 100 to prevent huge pipeline commands
		if len(keysToDelete) >= 100 {
			if err := r.deleteKeys(timeoutCtx, keysToDelete); err != nil {
				r.logger.Error("Failed to delete cache keys batch",
					logger.ErrorField(err),
					logger.Int("batch_size", len(keysToDelete)))
				return err
			}
			r.logger.Debug("Deleted batch of cache keys",
				logger.Int("count", len(keysToDelete)),
				logger.String("pattern", pattern))
			keysToDelete = keysToDelete[:0] // Clear slice but keep capacity
		}
	}

	// Delete any remaining keys
	if len(keysToDelete) > 0 {
		if err := r.deleteKeys(timeoutCtx, keysToDelete); err != nil {
			r.logger.Error("Failed to delete remaining cache keys",
				logger.ErrorField(err),
				logger.Int("count", len(keysToDelete)))
			return err
		}
		r.logger.Debug("Deleted remaining cache keys",
			logger.Int("count", len(keysToDelete)),
			logger.String("pattern", pattern))
	}

	if err := iter.Err(); err != nil {
		r.logger.Error("Error scanning Redis for keys",
			logger.ErrorField(err),
			logger.String("pattern", pattern))
		return fmt.Errorf("error scanning Redis for keys: %w", err)
	}

	r.logger.Info("Completed cache invalidation",
		logger.String("pattern", pattern),
		logger.Int("keys_scanned", keysScanned),
		logger.Int("keys_deleted", keysScanned))

	return nil
}

// deleteKeys is a helper method to delete multiple keys at once
func (r *RedisCostRepository) deleteKeys(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	for _, key := range keys {
		pipe.Del(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// FlushCache flushes specific cache patterns
// This is useful for maintenance and testing purposes
func (r *RedisCostRepository) FlushCache(ctx context.Context, pattern string, isGlobal bool) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// For safety, prevent complete cache flush unless explicitly requested
	if pattern == "*" && !isGlobal {
		return fmt.Errorf("refusing to flush entire cache without isGlobal flag")
	}

	r.logger.Info("Flushing cache with pattern",
		logger.String("pattern", pattern),
		logger.Bool("is_global", isGlobal))

	keys, err := r.scanKeys(ctx, pattern)
	if err != nil {
		r.logger.Error("Failed to scan keys for pattern",
			logger.ErrorField(err),
			logger.String("pattern", pattern))
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) == 0 {
		r.logger.Info("No keys found matching pattern",
			logger.String("pattern", pattern))
		return nil
	}

	// Log the count and sample of keys to be deleted
	keySample := keys
	if len(keySample) > 5 {
		keySample = keys[:5]
	}

	r.logger.Info("Flushing cache keys",
		logger.Int("count", len(keys)),
		logger.Any("sample_keys", keySample))

	// Delete keys in batches to avoid overwhelming Redis
	const batchSize = 100
	var deleteCount int64
	var lastErr error

	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		batch := keys[i:end]
		if len(batch) == 0 {
			continue
		}

		// Create a timeout context for this batch
		batchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)

		count, err := r.client.Del(batchCtx, batch...).Result()
		cancel()

		if err != nil {
			r.logger.Error("Failed to delete batch of keys",
				logger.ErrorField(err),
				logger.Int("batch_size", len(batch)),
				logger.Int("start_index", i))
			lastErr = err
			continue // Continue with next batch even if this one failed
		}

		deleteCount += count
	}

	if lastErr != nil {
		r.logger.Warn("Cache flush completed with errors",
			logger.ErrorField(lastErr),
			logger.Int("deleted_count", int(deleteCount)),
			logger.Int("total_keys", len(keys)))
		return fmt.Errorf("cache flush completed with errors: %w", lastErr)
	}

	r.logger.Info("Successfully flushed cache",
		logger.Int("deleted_count", int(deleteCount)),
		logger.Int("total_keys", len(keys)),
		logger.String("pattern", pattern))

	return nil
}

// scanKeys scans Redis for keys matching a pattern
func (r *RedisCostRepository) scanKeys(ctx context.Context, pattern string) ([]string, error) {
	var cursor uint64
	var keys []string
	var err error
	const batchSize = 100

	for {
		// Create a timeout context for each SCAN operation
		scanCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		var batch []string
		batch, cursor, err = r.client.Scan(scanCtx, cursor, pattern, batchSize).Result()
		cancel()

		if err != nil {
			return keys, fmt.Errorf("scan failed: %w", err)
		}

		keys = append(keys, batch...)

		// Check if the parent context has been canceled
		if err := ctx.Err(); err != nil {
			return keys, err
		}

		// Exit loop when cursor is 0
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}

// WithMetrics adds metrics collection to the RedisCostRepository
func (r *RedisCostRepository) WithMetrics(metrics MetricsCollector) CostRepository {
	return &RedisCostRepositoryWithMetrics{
		repository: r,
		metrics:    metrics,
	}
}

// RedisCostRepositoryWithMetrics wraps a RedisCostRepository with metrics
type RedisCostRepositoryWithMetrics struct {
	repository *RedisCostRepository
	metrics    MetricsCollector
}

// Ensure RedisCostRepositoryWithMetrics implements both CostRepository and RedisCacheOps interfaces
var (
	_ CostRepository = (*RedisCostRepositoryWithMetrics)(nil)
	_ RedisCacheOps  = (*RedisCostRepositoryWithMetrics)(nil)
)

// executeWithMetrics executes a function and records metrics
func (r *RedisCostRepositoryWithMetrics) executeWithMetrics(ctx context.Context, operation string, f func(ctx context.Context) error) error {
	startTime := time.Now()
	err := f(ctx)
	duration := time.Since(startTime)
	success := err == nil

	r.metrics.RecordDuration("cache_"+operation, duration, success)
	r.metrics.IncrementCounter("cache_"+operation, success)

	if success {
		r.metrics.IncrementCounter("cache_"+operation+"_success", true)
	} else {
		r.metrics.IncrementCounter("cache_"+operation+"_error", true)
		if errors.Is(err, redis.Nil) {
			r.metrics.IncrementCounter("cache_"+operation+"_miss", true)
		}
	}

	return err
}

// executeWithMetricsResult executes a function that returns a result and records metrics
func (r *RedisCostRepositoryWithMetrics) executeWithMetricsResult(ctx context.Context, operation string, f func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	startTime := time.Now()
	result, err := f(ctx)
	duration := time.Since(startTime)
	success := err == nil

	r.metrics.RecordDuration("cache_"+operation, duration, success)
	r.metrics.IncrementCounter("cache_"+operation, success)

	if success {
		r.metrics.IncrementCounter("cache_"+operation+"_success", true)
	} else {
		r.metrics.IncrementCounter("cache_"+operation+"_error", true)
		if errors.Is(err, redis.Nil) {
			r.metrics.IncrementCounter("cache_"+operation+"_miss", true)
		}
	}

	return result, err
}

// StoreCost implements CostRepository.StoreCost with metrics
func (r *RedisCostRepositoryWithMetrics) StoreCost(ctx context.Context, cost *domain.Cost) error {
	return r.executeWithMetrics(ctx, "StoreCost", func(ctx context.Context) error {
		return r.repository.StoreCost(ctx, cost)
	})
}

// StoreCosts implements CostRepository.StoreCosts with metrics
func (r *RedisCostRepositoryWithMetrics) StoreCosts(ctx context.Context, costs []*domain.Cost) error {
	r.metrics.ObserveValue("cache_batch_size", float64(len(costs)), map[string]string{
		"operation": "StoreCosts",
	})

	return r.executeWithMetrics(ctx, "StoreCosts", func(ctx context.Context) error {
		return r.repository.StoreCosts(ctx, costs)
	})
}

// GetCostByID implements CostRepository.GetCostByID with metrics
func (r *RedisCostRepositoryWithMetrics) GetCostByID(ctx context.Context, id string) (*domain.Cost, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Cost), err
}

// QueryCosts implements CostRepository.QueryCosts with metrics
func (r *RedisCostRepositoryWithMetrics) QueryCosts(ctx context.Context, query domain.CostQuery) ([]*domain.Cost, int, error) {
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

	r.metrics.ObserveValue("cache_result_size", float64(len(typedResult.costs)), map[string]string{
		"operation": "QueryCosts",
	})
	r.metrics.ObserveValue("cache_total_results", float64(typedResult.total), map[string]string{
		"operation": "QueryCosts",
	})

	return typedResult.costs, typedResult.total, nil
}

// GetCostSummary implements CostRepository.GetCostSummary with metrics
func (r *RedisCostRepositoryWithMetrics) GetCostSummary(ctx context.Context, query domain.CostQuery) (*domain.CostSummary, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostSummary", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostSummary(ctx, query)
	})

	if result == nil {
		return nil, err
	}

	summary := result.(*domain.CostSummary)
	if summary != nil {
		r.metrics.ObserveValue("cache_total_cost", summary.TotalCost, map[string]string{
			"operation": "GetCostSummary",
			"tenant_id": summary.TenantID,
		})
	}

	return summary, err
}

// CreateCostImport implements CostRepository.CreateCostImport with metrics
func (r *RedisCostRepositoryWithMetrics) CreateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	return r.executeWithMetrics(ctx, "CreateCostImport", func(ctx context.Context) error {
		return r.repository.CreateCostImport(ctx, costImport)
	})
}

// UpdateCostImport implements CostRepository.UpdateCostImport with metrics
func (r *RedisCostRepositoryWithMetrics) UpdateCostImport(ctx context.Context, costImport *domain.CostImport) error {
	return r.executeWithMetrics(ctx, "UpdateCostImport", func(ctx context.Context) error {
		return r.repository.UpdateCostImport(ctx, costImport)
	})
}

// GetCostImportByID implements CostRepository.GetCostImportByID with metrics
func (r *RedisCostRepositoryWithMetrics) GetCostImportByID(ctx context.Context, id string) (*domain.CostImport, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetCostImportByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetCostImportByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.CostImport), err
}

// ListCostImports implements CostRepository.ListCostImports with metrics
func (r *RedisCostRepositoryWithMetrics) ListCostImports(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, page, pageSize int) ([]*domain.CostImport, int, error) {
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

	r.metrics.ObserveValue("cache_result_size", float64(len(typedResult.imports)), map[string]string{
		"operation": "ListCostImports",
	})

	return typedResult.imports, typedResult.total, nil
}

// CreateBudget implements CostRepository.CreateBudget with metrics
func (r *RedisCostRepositoryWithMetrics) CreateBudget(ctx context.Context, budget *domain.Budget) error {
	return r.executeWithMetrics(ctx, "CreateBudget", func(ctx context.Context) error {
		return r.repository.CreateBudget(ctx, budget)
	})
}

// UpdateBudget implements CostRepository.UpdateBudget with metrics
func (r *RedisCostRepositoryWithMetrics) UpdateBudget(ctx context.Context, budget *domain.Budget) error {
	return r.executeWithMetrics(ctx, "UpdateBudget", func(ctx context.Context) error {
		return r.repository.UpdateBudget(ctx, budget)
	})
}

// DeleteBudget implements CostRepository.DeleteBudget with metrics
func (r *RedisCostRepositoryWithMetrics) DeleteBudget(ctx context.Context, id string) error {
	return r.executeWithMetrics(ctx, "DeleteBudget", func(ctx context.Context) error {
		return r.repository.DeleteBudget(ctx, id)
	})
}

// GetBudgetByID implements CostRepository.GetBudgetByID with metrics
func (r *RedisCostRepositoryWithMetrics) GetBudgetByID(ctx context.Context, id string) (*domain.Budget, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetBudgetByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetBudgetByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Budget), err
}

// ListBudgets implements CostRepository.ListBudgets with metrics
func (r *RedisCostRepositoryWithMetrics) ListBudgets(ctx context.Context, tenantID string, provider domain.CloudProvider, active bool, page, pageSize int) ([]*domain.Budget, int, error) {
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

	r.metrics.ObserveValue("cache_result_size", float64(len(typedResult.budgets)), map[string]string{
		"operation": "ListBudgets",
	})

	return typedResult.budgets, typedResult.total, nil
}

// CreateAnomaly implements CostRepository.CreateAnomaly with metrics
func (r *RedisCostRepositoryWithMetrics) CreateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	return r.executeWithMetrics(ctx, "CreateAnomaly", func(ctx context.Context) error {
		return r.repository.CreateAnomaly(ctx, anomaly)
	})
}

// UpdateAnomaly implements CostRepository.UpdateAnomaly with metrics
func (r *RedisCostRepositoryWithMetrics) UpdateAnomaly(ctx context.Context, anomaly *domain.Anomaly) error {
	return r.executeWithMetrics(ctx, "UpdateAnomaly", func(ctx context.Context) error {
		return r.repository.UpdateAnomaly(ctx, anomaly)
	})
}

// GetAnomalyByID implements CostRepository.GetAnomalyByID with metrics
func (r *RedisCostRepositoryWithMetrics) GetAnomalyByID(ctx context.Context, id string) (*domain.Anomaly, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetAnomalyByID", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetAnomalyByID(ctx, id)
	})

	if result == nil {
		return nil, err
	}

	return result.(*domain.Anomaly), err
}

// ListAnomalies implements CostRepository.ListAnomalies with metrics
func (r *RedisCostRepositoryWithMetrics) ListAnomalies(ctx context.Context, tenantID string, provider domain.CloudProvider, startTime, endTime time.Time, status string, page, pageSize int) ([]*domain.Anomaly, int, error) {
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

	r.metrics.ObserveValue("cache_result_size", float64(len(typedResult.anomalies)), map[string]string{
		"operation": "ListAnomalies",
	})

	return typedResult.anomalies, typedResult.total, nil
}

// StoreForecast implements CostRepository.StoreForecast with metrics
func (r *RedisCostRepositoryWithMetrics) StoreForecast(ctx context.Context, forecast *domain.Forecast) error {
	return r.executeWithMetrics(ctx, "StoreForecast", func(ctx context.Context) error {
		return r.repository.StoreForecast(ctx, forecast)
	})
}

// GetForecast implements CostRepository.GetForecast with metrics
func (r *RedisCostRepositoryWithMetrics) GetForecast(ctx context.Context, tenantID string, provider domain.CloudProvider, accountID string, startTime, endTime time.Time) (*domain.Forecast, error) {
	result, err := r.executeWithMetricsResult(ctx, "GetForecast", func(ctx context.Context) (interface{}, error) {
		return r.repository.GetForecast(ctx, tenantID, provider, accountID, startTime, endTime)
	})

	if result == nil {
		return nil, err
	}

	forecast := result.(*domain.Forecast)
	if forecast != nil {
		r.metrics.ObserveValue("cache_forecasted_cost", forecast.ForecastedCost, map[string]string{
			"operation": "GetForecast",
			"tenant_id": forecast.TenantID,
		})
	}

	return forecast, err
}

// HealthCheck implements CostRepository.HealthCheck with metrics
func (r *RedisCostRepositoryWithMetrics) HealthCheck(ctx context.Context) error {
	return r.executeWithMetrics(ctx, "HealthCheck", func(ctx context.Context) error {
		return r.repository.HealthCheck(ctx)
	})
}

// FlushCache implements RedisCacheOps.FlushCache with metrics
// This provides the same interface as the underlying RedisCostRepository
func (r *RedisCostRepositoryWithMetrics) FlushCache(ctx context.Context, pattern string, isGlobal bool) error {
	startTime := time.Now()
	err := r.repository.FlushCache(ctx, pattern, isGlobal)
	duration := time.Since(startTime)
	success := err == nil

	r.metrics.RecordDuration("cache_FlushCache", duration, success)
	r.metrics.IncrementCounter("cache_FlushCache", success)

	if pattern != "" {
		r.metrics.IncrementCounter("cache_flush_pattern", success)
	}
	if isGlobal {
		r.metrics.IncrementCounter("cache_flush_global", success)
	}

	return err
}

// RedisCacheOps defines Redis-specific cache operations
type RedisCacheOps interface {
	FlushCache(ctx context.Context, pattern string, isGlobal bool) error
}

// AsRedisCacheOps attempts to convert a CostRepository to RedisCacheOps
func AsRedisCacheOps(repo CostRepository) (RedisCacheOps, bool) {
	if redisRepo, ok := repo.(*RedisCostRepository); ok {
		return redisRepo, true
	}

	if wrappedRepo, ok := repo.(*RedisCostRepositoryWithMetrics); ok {
		return wrappedRepo.repository, true
	}

	return nil, false
}

// CacheTTLStrategy defines how TTL is determined for different types of data
type CacheTTLStrategy struct {
	// DefaultTTL is the default cache TTL
	DefaultTTL time.Duration

	// IdTTL is the TTL for individual resource fetches by ID
	IdTTL time.Duration

	// QueryTTL is the TTL for query results
	QueryTTL time.Duration

	// SummaryTTL is the TTL for aggregated data like summaries
	SummaryTTL time.Duration

	// ForecastTTL is the TTL for forecast data
	ForecastTTL time.Duration

	// EmptyResultTTL is the TTL for empty result sets (to prevent hammering the database)
	EmptyResultTTL time.Duration

	// HighCardinalityMaxTTL is the maximum TTL for high cardinality queries
	HighCardinalityMaxTTL time.Duration

	// FrequentChangeMaxTTL is the maximum TTL for frequently changing data
	FrequentChangeMaxTTL time.Duration

	// ReadOnlyTTL is the TTL for read-only or historical data
	ReadOnlyTTL time.Duration
}

// DefaultCacheTTLStrategy returns sensible defaults for TTL strategy
func DefaultCacheTTLStrategy() CacheTTLStrategy {
	return CacheTTLStrategy{
		DefaultTTL:            1 * time.Hour,
		IdTTL:                 2 * time.Hour,
		QueryTTL:              30 * time.Minute,
		SummaryTTL:            3 * time.Hour,
		ForecastTTL:           6 * time.Hour,
		EmptyResultTTL:        5 * time.Minute,
		HighCardinalityMaxTTL: 15 * time.Minute,
		FrequentChangeMaxTTL:  10 * time.Minute,
		ReadOnlyTTL:           24 * time.Hour,
	}
}
