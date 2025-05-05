package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

var (
	// ErrCacheMiss represents a cache miss (key not found)
	ErrCacheMiss = errors.New("cache miss")

	// ErrCacheInvalidData represents invalid cached data format
	ErrCacheInvalidData = errors.New("invalid cache data format")

	// Cache metrics for Prometheus
	cacheOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_cache_operations_total",
			Help: "Total number of Redis cache operations",
		},
		[]string{"operation", "status"},
	)

	cacheHitRate = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_cache_hit_rate",
			Help: "Cache hit rate",
		},
		[]string{"operation"},
	)

	cacheOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_cache_operation_duration_seconds",
			Help:    "Duration of Redis cache operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(cacheOperations)
	prometheus.MustRegister(cacheHitRate)
	prometheus.MustRegister(cacheOperationDuration)
}

// RedisCache provides a production-grade Redis-based caching mechanism
type RedisCache struct {
	client *redis.Client
	logger *logger.Logger
	prefix string
}

// NewRedisCache creates a new Redis cache with the given client and optional prefix
func NewRedisCache(client *redis.Client, logger *logger.Logger, prefix string) (*RedisCache, error) {
	if client == nil {
		return nil, errors.New("redis client cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	return &RedisCache{
		client: client,
		logger: logger,
		prefix: prefix,
	}, nil
}

// formattedKey formats a cache key with the prefix
func (c *RedisCache) formattedKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return c.prefix + ":" + key
}

// Set adds or updates a value in the cache with the specified TTL
func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("set").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	jsonData, err := json.Marshal(value)
	if err != nil {
		c.logger.Error("Failed to marshal cache data",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set", "error").Inc()
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	err = c.client.Set(ctx, formattedKey, jsonData, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set cache data",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set", "error").Inc()
		return fmt.Errorf("failed to set cache: %w", err)
	}

	c.logger.Debug("Cache set successful",
		logger.String("key", key),
		logger.Duration("ttl", ttl),
	)
	cacheOperations.WithLabelValues("set", "success").Inc()
	return nil
}

// Get retrieves a value from the cache and unmarshals it into the result
func (c *RedisCache) Get(ctx context.Context, key string, result interface{}) error {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("get").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	jsonData, err := c.client.Get(ctx, formattedKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			cacheOperations.WithLabelValues("get", "miss").Inc()
			cacheHitRate.WithLabelValues("miss").Inc()
			return ErrCacheMiss
		}

		c.logger.Error("Failed to get cache data",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("get", "error").Inc()
		return fmt.Errorf("failed to get cache: %w", err)
	}

	if err := json.Unmarshal(jsonData, result); err != nil {
		c.logger.Error("Failed to unmarshal cache data",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("get", "invalid_data").Inc()
		return fmt.Errorf("%w: %v", ErrCacheInvalidData, err)
	}

	c.logger.Debug("Cache hit",
		logger.String("key", key),
	)
	cacheOperations.WithLabelValues("get", "hit").Inc()
	cacheHitRate.WithLabelValues("hit").Inc()
	return nil
}

// Delete removes a value from the cache
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("delete").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	err := c.client.Del(ctx, formattedKey).Err()
	if err != nil {
		c.logger.Error("Failed to delete cache data",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("delete", "error").Inc()
		return fmt.Errorf("failed to delete cache: %w", err)
	}

	c.logger.Debug("Cache delete successful",
		logger.String("key", key),
	)
	cacheOperations.WithLabelValues("delete", "success").Inc()
	return nil
}

// SetMulti sets multiple key-value pairs in the cache with the same TTL
func (c *RedisCache) SetMulti(ctx context.Context, keyValues map[string]interface{}, ttl time.Duration) error {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("set_multi").Observe(time.Since(startTime).Seconds())
	}()

	if len(keyValues) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	for key, value := range keyValues {
		formattedKey := c.formattedKey(key)
		jsonData, err := json.Marshal(value)
		if err != nil {
			c.logger.Error("Failed to marshal cache data for multi-set",
				logger.String("key", key),
				logger.ErrorField(err),
			)
			continue
		}
		pipe.Set(ctx, formattedKey, jsonData, ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		c.logger.Error("Failed to execute multi-set pipeline",
			logger.Int("key_count", len(keyValues)),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set_multi", "error").Inc()
		return fmt.Errorf("failed to set multiple cache entries: %w", err)
	}

	c.logger.Debug("Cache multi-set successful",
		logger.Int("key_count", len(keyValues)),
		logger.Duration("ttl", ttl),
	)
	cacheOperations.WithLabelValues("set_multi", "success").Inc()
	return nil
}

// GetMulti retrieves multiple values from the cache
func (c *RedisCache) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("get_multi").Observe(time.Since(startTime).Seconds())
	}()

	if len(keys) == 0 {
		return map[string][]byte{}, nil
	}

	formattedKeys := make([]string, len(keys))
	keyMap := make(map[string]string) // Maps formatted keys back to original keys

	for i, key := range keys {
		formattedKey := c.formattedKey(key)
		formattedKeys[i] = formattedKey
		keyMap[formattedKey] = key
	}

	pipe := c.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd)

	for _, formattedKey := range formattedKeys {
		cmds[formattedKey] = pipe.Get(ctx, formattedKey)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		c.logger.Error("Failed to execute multi-get pipeline",
			logger.Int("key_count", len(keys)),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("get_multi", "error").Inc()
		return nil, fmt.Errorf("failed to get multiple cache entries: %w", err)
	}

	result := make(map[string][]byte)
	hitCount := 0

	for formattedKey, cmd := range cmds {
		originalKey := keyMap[formattedKey]
		data, err := cmd.Bytes()

		if err == nil {
			result[originalKey] = data
			hitCount++
		} else if err != redis.Nil {
			c.logger.Warn("Error getting cache entry",
				logger.String("key", originalKey),
				logger.ErrorField(err),
			)
		}
	}

	c.logger.Debug("Cache multi-get completed",
		logger.Int("requested", len(keys)),
		logger.Int("hits", hitCount),
	)

	cacheOperations.WithLabelValues("get_multi", "success").Inc()
	cacheHitRate.WithLabelValues("hit").Add(float64(hitCount))
	cacheHitRate.WithLabelValues("miss").Add(float64(len(keys) - hitCount))

	return result, nil
}

// Exists checks if a key exists in the cache
func (c *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("exists").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	count, err := c.client.Exists(ctx, formattedKey).Result()
	if err != nil {
		c.logger.Error("Failed to check cache key existence",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("exists", "error").Inc()
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	exists := count > 0
	status := "hit"
	if !exists {
		status = "miss"
	}

	c.logger.Debug("Cache existence check",
		logger.String("key", key),
		logger.Bool("exists", exists),
	)

	cacheOperations.WithLabelValues("exists", "success").Inc()
	cacheHitRate.WithLabelValues(status).Inc()

	return exists, nil
}

// SetWithLock atomically sets a value only if it doesn't exist with NX option
func (c *RedisCache) SetWithLock(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("set_with_lock").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	jsonData, err := json.Marshal(value)
	if err != nil {
		c.logger.Error("Failed to marshal cache data for lock",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set_with_lock", "error").Inc()
		return false, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Use SetNX for atomic lock acquisition
	result, err := c.client.SetNX(ctx, formattedKey, jsonData, ttl).Result()
	if err != nil {
		c.logger.Error("Failed to set cache lock",
			logger.String("key", key),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set_with_lock", "error").Inc()
		return false, fmt.Errorf("failed to set lock: %w", err)
	}

	status := "acquired"
	if !result {
		status = "not_acquired"
	}

	c.logger.Debug("Cache lock attempt",
		logger.String("key", key),
		logger.Bool("acquired", result),
	)

	cacheOperations.WithLabelValues("set_with_lock", status).Inc()
	return result, nil
}

// Increment increments a numeric counter by the specified amount
func (c *RedisCache) Increment(ctx context.Context, key string, value int64) (int64, error) {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("increment").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	result, err := c.client.IncrBy(ctx, formattedKey, value).Result()
	if err != nil {
		c.logger.Error("Failed to increment cache counter",
			logger.String("key", key),
			logger.Any("value", value),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("increment", "error").Inc()
		return 0, fmt.Errorf("failed to increment counter: %w", err)
	}

	c.logger.Debug("Cache counter incremented",
		logger.String("key", key),
		logger.Any("increment", value),
		logger.Any("new_value", result),
	)

	cacheOperations.WithLabelValues("increment", "success").Inc()
	return result, nil
}

// SetTTL updates the TTL of an existing key
func (c *RedisCache) SetTTL(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("set_ttl").Observe(time.Since(startTime).Seconds())
	}()

	formattedKey := c.formattedKey(key)
	result, err := c.client.Expire(ctx, formattedKey, ttl).Result()
	if err != nil {
		c.logger.Error("Failed to set cache TTL",
			logger.String("key", key),
			logger.Duration("ttl", ttl),
			logger.ErrorField(err),
		)
		cacheOperations.WithLabelValues("set_ttl", "error").Inc()
		return false, fmt.Errorf("failed to set TTL: %w", err)
	}

	c.logger.Debug("Cache TTL update",
		logger.String("key", key),
		logger.Duration("ttl", ttl),
		logger.Bool("success", result),
	)

	status := "success"
	if !result {
		status = "key_not_found"
	}

	cacheOperations.WithLabelValues("set_ttl", status).Inc()
	return result, nil
}

// Flush deletes all keys with the cache prefix
func (c *RedisCache) Flush(ctx context.Context) error {
	startTime := time.Now()
	defer func() {
		cacheOperationDuration.WithLabelValues("flush").Observe(time.Since(startTime).Seconds())
	}()

	var cursor uint64
	var err error
	pattern := c.prefix + ":*"

	if c.prefix == "" {
		c.logger.Warn("Flush called with empty prefix - refusing to delete all Redis keys")
		return errors.New("cannot flush cache with empty prefix")
	}

	deletedCount := 0
	for {
		var keys []string
		keys, cursor, err = c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			c.logger.Error("Failed to scan keys during flush",
				logger.String("pattern", pattern),
				logger.ErrorField(err),
			)
			cacheOperations.WithLabelValues("flush", "error").Inc()
			return fmt.Errorf("failed to scan keys: %w", err)
		}

		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
				c.logger.Error("Failed to delete keys during flush",
					logger.Any("keys", keys),
					logger.ErrorField(err),
				)
				cacheOperations.WithLabelValues("flush", "error").Inc()
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			deletedCount += len(keys)
		}

		if cursor == 0 {
			break
		}
	}

	c.logger.Info("Cache flush completed",
		logger.String("pattern", pattern),
		logger.Int("deleted_count", deletedCount),
	)

	cacheOperations.WithLabelValues("flush", "success").Inc()
	return nil
}
