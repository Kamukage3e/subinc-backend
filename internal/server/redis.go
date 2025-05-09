package server

import (
	"context"

	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(redisOperations)
	prometheus.MustRegister(redisOperationDuration)
	prometheus.MustRegister(redisConnectionsActive)
}

// NewRedisConfig creates a production-ready Redis configuration from environment or viper
func NewRedisConfig(log *logger.Logger) (*RedisConfig, error) {
	// Try Viper only, no direct os.Getenv
	url := viper.GetString("redis.url")
	if url == "" {
		// no fallback
	}

	host := viper.GetString("redis.host")
	if host == "" {
		host = "localhost" // Reasonable default for local dev
	}

	port := viper.GetString("redis.port")
	if port == "" {
		port = "6379" // Redis default port
	}

	password := viper.GetString("redis.password")

	dbStr := viper.GetString("redis.db")
	db := 0
	if dbStr != "" {
		var err error
		db, err = strconv.Atoi(dbStr)
		if err != nil {
			log.Warn("invalid redis.db value, using default (0)", logger.String("value", dbStr), logger.ErrorField(err))
		}
	}

	maxRetriesStr := viper.GetString("redis.max_retries")
	maxRetries := 3 // Reasonable default
	if maxRetriesStr != "" {
		var err error
		maxRetries, err = strconv.Atoi(maxRetriesStr)
		if err != nil {
			log.Warn("invalid redis.max_retries value, using default", logger.String("value", maxRetriesStr), logger.ErrorField(err))
		}
	}

	minIdleConnsStr := viper.GetString("redis.min_idle_conns")
	minIdleConns := 10 // Reasonable default for production
	if minIdleConnsStr != "" {
		var err error
		minIdleConns, err = strconv.Atoi(minIdleConnsStr)
		if err != nil {
			log.Warn("invalid redis.min_idle_conns value, using default", logger.String("value", minIdleConnsStr), logger.ErrorField(err))
		}
	}

	poolSizeStr := viper.GetString("redis.pool_size")
	poolSize := 50 // Reasonable default for production
	if poolSizeStr != "" {
		var err error
		poolSize, err = strconv.Atoi(poolSizeStr)
		if err != nil {
			log.Warn("invalid redis.pool_size value, using default", logger.String("value", poolSizeStr), logger.ErrorField(err))
		}
	}

	dialTimeout := 5 * time.Second
	readTimeout := 3 * time.Second
	writeTimeout := 3 * time.Second
	poolTimeout := 4 * time.Second
	connMaxIdleTime := 10 * time.Minute
	connMaxLifetime := 30 * time.Minute

	return &RedisConfig{
		URL:             url,
		Host:            host,
		Port:            port,
		Password:        password,
		DB:              db,
		MaxRetries:      maxRetries,
		MinIdleConns:    minIdleConns,
		PoolSize:        poolSize,
		PoolTimeout:     poolTimeout,
		DialTimeout:     dialTimeout,
		ReadTimeout:     readTimeout,
		WriteTimeout:    writeTimeout,
		ConnMaxIdleTime: connMaxIdleTime,
		ConnMaxLifetime: connMaxLifetime,
	}, nil
}

// ValidateRedisConfig performs validation checks on the Redis configuration
func ValidateRedisConfig(config *RedisConfig) error {
	if config.URL == "" && (config.Host == "" || config.Port == "") {
		return fmt.Errorf("Redis configuration invalid: URL or Host+Port must be provided")
	}

	// Validate timeout values
	if config.DialTimeout <= 0 || config.ReadTimeout <= 0 || config.WriteTimeout <= 0 {
		return fmt.Errorf("Redis configuration invalid: timeouts must be positive")
	}

	// Validate connection pool parameters
	if config.PoolSize <= 0 {
		return fmt.Errorf("Redis configuration invalid: pool size must be positive")
	}

	return nil
}

// NewRedisClient returns a production-ready Redis client with connection pooling, error handling, and metrics
func NewRedisClient(log *logger.Logger) (*redis.Client, error) {
	config, err := NewRedisConfig(log)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedisConnection, err)
	}

	if err := ValidateRedisConfig(config); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedisConnection, err)
	}

	// Construct client options based on URL or Host+Port
	var client *redis.Client
	if config.URL != "" {
		opt, err := redis.ParseURL(config.URL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid REDIS_URL: %v", ErrRedisConnection, err)
		}

		// Apply additional configurations not covered by URL
		opt.MaxRetries = config.MaxRetries
		opt.MinIdleConns = config.MinIdleConns
		opt.PoolSize = config.PoolSize
		opt.PoolTimeout = config.PoolTimeout
		opt.ConnMaxIdleTime = config.ConnMaxIdleTime
		opt.ConnMaxLifetime = config.ConnMaxLifetime

		client = redis.NewClient(opt)
	} else {
		client = redis.NewClient(&redis.Options{
			Addr:            fmt.Sprintf("%s:%s", config.Host, config.Port),
			Password:        config.Password,
			DB:              config.DB,
			MaxRetries:      config.MaxRetries,
			MinIdleConns:    config.MinIdleConns,
			PoolSize:        config.PoolSize,
			PoolTimeout:     config.PoolTimeout,
			DialTimeout:     config.DialTimeout,
			ReadTimeout:     config.ReadTimeout,
			WriteTimeout:    config.WriteTimeout,
			ConnMaxIdleTime: config.ConnMaxIdleTime,
			ConnMaxLifetime: config.ConnMaxLifetime,
		})
	}

	// Use hooks for metrics and logging
	client.AddHook(&RedisHook{logger: log})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedisConnection, err)
	}

	log.Info("Redis connection established successfully",
		logger.String("host", config.Host),
		logger.String("port", config.Port),
		logger.Int("pool_size", config.PoolSize),
	)

	return client, nil
}

// RedisHealthCheck performs a comprehensive Redis health check with metrics
func RedisHealthCheck(ctx context.Context, client *redis.Client) error {
	if client == nil {
		return fmt.Errorf("%w: client is nil", ErrRedisOperation)
	}

	start := time.Now()
	err := client.Ping(ctx).Err()
	duration := time.Since(start)

	// Record metrics
	status := "success"
	if err != nil {
		status = "error"
	}
	redisOperations.WithLabelValues("ping", status).Inc()
	redisOperationDuration.WithLabelValues("ping").Observe(duration.Seconds())

	if err != nil {
		return fmt.Errorf("%w: ping failed: %v", ErrRedisOperation, err)
	}

	// Get pool stats
	poolStats := client.PoolStats()
	redisConnectionsActive.Set(float64(poolStats.TotalConns - poolStats.IdleConns))

	return nil
}

// BeforeProcess logs and records metrics before each Redis command
func (hook *RedisHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	return context.WithValue(ctx, redisContextKey("start_time"), time.Now()), nil
}

// AfterProcess logs and records metrics after each Redis command
func (hook *RedisHook) AfterProcess(ctx context.Context, cmd redis.Cmder) error {
	startTime, _ := ctx.Value(redisContextKey("start_time")).(time.Time)
	if !startTime.IsZero() {
		duration := time.Since(startTime)
		cmdName := cmd.Name()

		status := "success"
		if err := cmd.Err(); err != nil && err != redis.Nil {
			status = "error"
			hook.logger.Debug("Redis command failed",
				logger.String("command", cmdName),
				logger.ErrorField(err),
				logger.Duration("duration", duration),
			)
		}

		redisOperations.WithLabelValues(cmdName, status).Inc()
		redisOperationDuration.WithLabelValues(cmdName).Observe(duration.Seconds())
	}
	return nil
}

// BeforeProcessPipeline logs and records metrics before pipeline commands
func (hook *RedisHook) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	return context.WithValue(ctx, redisContextKey("pipeline_start_time"), time.Now()), nil
}

// AfterProcessPipeline logs and records metrics after pipeline commands
func (hook *RedisHook) AfterProcessPipeline(ctx context.Context, cmds []redis.Cmder) error {
	startTime, _ := ctx.Value(redisContextKey("pipeline_start_time")).(time.Time)
	if !startTime.IsZero() {
		duration := time.Since(startTime)

		// Count errors
		errorCount := 0
		for _, cmd := range cmds {
			if err := cmd.Err(); err != nil && err != redis.Nil {
				errorCount++
			}
		}

		status := "success"
		if errorCount > 0 {
			status = "error"
			hook.logger.Debug("Redis pipeline had errors",
				logger.Int("total_commands", len(cmds)),
				logger.Int("error_count", errorCount),
				logger.Duration("duration", duration),
			)
		}

		redisOperations.WithLabelValues("pipeline", status).Inc()
		redisOperationDuration.WithLabelValues("pipeline").Observe(duration.Seconds())
	}
	return nil
}

// ProcessHook is called when custom command processing is required
func (hook *RedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		startTime := time.Now()
		err := next(ctx, cmd)
		duration := time.Since(startTime)

		cmdName := cmd.Name()
		status := "success"
		if err != nil && err != redis.Nil {
			status = "error"
			hook.logger.Debug("Redis process hook failed",
				logger.String("command", cmdName),
				logger.ErrorField(err),
				logger.Duration("duration", duration),
			)
		}

		redisOperations.WithLabelValues(cmdName+"_process", status).Inc()
		redisOperationDuration.WithLabelValues(cmdName + "_process").Observe(duration.Seconds())

		return err
	}
}

// DialHook is called when a new connection is established
func (hook *RedisHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		startTime := time.Now()
		conn, err := next(ctx, network, addr)
		duration := time.Since(startTime)

		status := "success"
		if err != nil {
			status = "error"
			hook.logger.Debug("Redis dial failed",
				logger.String("network", network),
				logger.String("addr", addr),
				logger.ErrorField(err),
				logger.Duration("duration", duration),
			)
		} else {
			hook.logger.Debug("Redis dial succeeded",
				logger.String("network", network),
				logger.String("addr", addr),
				logger.Duration("duration", duration),
			)
		}

		redisOperations.WithLabelValues("dial", status).Inc()
		redisOperationDuration.WithLabelValues("dial").Observe(duration.Seconds())

		return conn, err
	}
}

// ProcessPipelineHook is called when custom pipeline processing is required
func (hook *RedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		startTime := time.Now()
		err := next(ctx, cmds)
		duration := time.Since(startTime)

		status := "success"
		if err != nil {
			status = "error"
			hook.logger.Debug("Redis pipeline process hook failed",
				logger.Int("commands", len(cmds)),
				logger.ErrorField(err),
				logger.Duration("duration", duration),
			)
		}

		redisOperations.WithLabelValues("pipeline_process", status).Inc()
		redisOperationDuration.WithLabelValues("pipeline_process").Observe(duration.Seconds())

		return err
	}
}
