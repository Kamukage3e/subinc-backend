package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	. "github.com/subinc/subinc-backend/internal/pkg/logger"
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(rateLimitTotal)
	prometheus.MustRegister(rateLimitRemaining)
	prometheus.MustRegister(rateLimitErrors)
}

// NewDefaultRateLimiterConfig creates a config with sensible defaults
func NewDefaultRateLimiterConfig(redisClient *redis.Client, logger *Logger) (*RateLimiterConfig, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("Redis client cannot be nil for rate limiter")
	}
	if logger == nil {
		return nil, fmt.Errorf("Logger cannot be nil for rate limiter")
	}

	// Read config from viper if available
	maxRequests := viper.GetInt("rate_limit.max_requests")
	if maxRequests <= 0 {
		maxRequests = 100 // Default: 100 requests per minute
	}

	window := viper.GetDuration("rate_limit.window")
	if window <= 0 {
		window = time.Minute // Default: 1 minute window
	}

	keyPrefix := viper.GetString("rate_limit.key_prefix")
	if keyPrefix == "" {
		keyPrefix = "rl:" // Default prefix for rate limit keys
	}

	return &RateLimiterConfig{
		RedisClient: redisClient,
		Logger:      logger,
		MaxRequests: maxRequests,
		Window:      window,
		KeyPrefix:   keyPrefix,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() // Default: IP-based rate limiting
		},
		LimitReachedHandler: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   "Too many requests",
				"message": "Rate limit exceeded. Please try again later.",
			})
		},
		SkipFunc: func(c *fiber.Ctx) bool {
			return false // Default: Don't skip any requests
		},
		Headers: true, // Default: Include rate limit headers
	}, nil
}

// NewRateLimiterStore creates a Redis-backed store for rate limiting
func NewRateLimiterStore(client *redis.Client, keyPrefix string, logger *Logger) *RateLimiterStore {
	return &RateLimiterStore{
		client:    client,
		keyPrefix: keyPrefix,
		logger:    logger,
	}
}

// RateLimit creates a rate limiting middleware with Redis backend
func RateLimit(config *RateLimiterConfig) fiber.Handler {
	// Set default config
	if config == nil {
		panic("Rate limiter config cannot be nil")
	}

	store := NewRateLimiterStore(config.RedisClient, config.KeyPrefix, config.Logger)

	// Return middleware handler
	return func(c *fiber.Ctx) error {
		// Check if request should be skipped
		if config.SkipFunc != nil && config.SkipFunc(c) {
			return c.Next()
		}

		// Get key for rate limiting
		key := config.KeyPrefix + config.KeyGenerator(c)

		// Get request count and TTL from Redis
		remaining, resetTime, err := store.Get(c.Context(), key, config.MaxRequests, config.Window)
		if err != nil {
			// Log error but allow request to proceed
			config.Logger.Error("Rate limit store error",
				String("key", key),
				ErrorField(err),
			)
			rateLimitErrors.Inc()
			return c.Next()
		}

		// Set headers if enabled
		if config.Headers {
			// X-RateLimit-Reset: Time in seconds until reset (UTC epoch seconds)
			c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))
			// X-RateLimit-Limit: Maximum requests allowed
			c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.MaxRequests))
			// X-RateLimit-Remaining: Remaining requests
			c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		}

		// Record metrics
		if remaining <= 0 {
			rateLimitTotal.WithLabelValues("exceeded").Inc()
			return config.LimitReachedHandler(c)
		}

		rateLimitTotal.WithLabelValues("allowed").Inc()

		return c.Next()
	}
}

// Get retrieves the current request count for a key
// Returns remaining requests, reset time (epoch seconds), and error
func (s *RateLimiterStore) Get(ctx context.Context, key string, max int, window time.Duration) (int, int64, error) {
	now := time.Now().Unix()
	resetTime := now + int64(window.Seconds())

	// Using Redis pipeline for efficiency
	pipe := s.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	ttl := pipe.TTL(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return max, resetTime, err
	}

	// Get results from pipeline
	val, err := incr.Result()
	if err != nil {
		return max, resetTime, err
	}

	// Get TTL, which tells us when the key expires
	expiry, err := ttl.Result()
	if err != nil && err != redis.Nil {
		return max, resetTime, err
	}

	// Calculate reset time based on TTL
	if expiry > 0 {
		resetTime = now + int64(expiry.Seconds())
	}

	// Calculate remaining requests
	remaining := max - int(val)
	if remaining < 0 {
		remaining = 0
	}

	return remaining, resetTime, nil
}

// CustomRateLimiters provides specialized rate limiters for different routes

// IPRateLimiter creates a rate limiter based on client IP
func IPRateLimiter(client *redis.Client, logger *Logger, maxRequests int, window time.Duration) fiber.Handler {
	config, err := NewDefaultRateLimiterConfig(client, logger)
	if err != nil {
		logger.Error("Failed to create rate limiter config", ErrorField(err))
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limiter misconfiguration"})
		}
	}
	config.MaxRequests = maxRequests
	config.Window = window
	config.KeyPrefix = "rl:ip:"
	return RateLimit(config)
}

// APIKeyRateLimiter creates a rate limiter based on API key
func APIKeyRateLimiter(client *redis.Client, logger *Logger, maxRequests int, window time.Duration) fiber.Handler {
	config, err := NewDefaultRateLimiterConfig(client, logger)
	if err != nil {
		logger.Error("Failed to create rate limiter config", ErrorField(err))
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limiter misconfiguration"})
		}
	}
	config.MaxRequests = maxRequests
	config.Window = window
	config.KeyPrefix = "rl:apikey:"
	config.KeyGenerator = func(c *fiber.Ctx) string {
		apiKey := c.Get("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}
		if apiKey == "" {
			return "anonymous"
		}
		return apiKey
	}
	return RateLimit(config)
}

// RouteRateLimiter creates a rate limiter based on route path
func RouteRateLimiter(client *redis.Client, logger *Logger, maxRequests int, window time.Duration) fiber.Handler {
	config, err := NewDefaultRateLimiterConfig(client, logger)
	if err != nil {
		logger.Error("Failed to create rate limiter config", ErrorField(err))
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limiter misconfiguration"})
		}
	}
	config.MaxRequests = maxRequests
	config.Window = window
	config.KeyPrefix = "rl:route:"
	config.KeyGenerator = func(c *fiber.Ctx) string {
		return c.Path()
	}
	return RateLimit(config)
}

// TenantRateLimiter creates a rate limiter based on tenant ID
func TenantRateLimiter(client *redis.Client, logger *Logger, maxRequests int, window time.Duration) fiber.Handler {
	config, err := NewDefaultRateLimiterConfig(client, logger)
	if err != nil {
		logger.Error("Failed to create rate limiter config", ErrorField(err))
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limiter misconfiguration"})
		}
	}
	config.MaxRequests = maxRequests
	config.Window = window
	config.KeyPrefix = "rl:tenant:"
	config.KeyGenerator = func(c *fiber.Ctx) string {
		tenantID, ok := c.Locals("tenant_id").(string)
		if !ok || tenantID == "" {
			return "anonymous"
		}
		return tenantID
	}
	return RateLimit(config)
}

// CombinedRateLimiter creates a rate limiter based on IP and route
func CombinedRateLimiter(client *redis.Client, logger *Logger, maxRequests int, window time.Duration) fiber.Handler {
	config, err := NewDefaultRateLimiterConfig(client, logger)
	if err != nil {
		logger.Error("Failed to create rate limiter config", ErrorField(err))
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "rate limiter misconfiguration"})
		}
	}
	config.MaxRequests = maxRequests
	config.Window = window
	config.KeyPrefix = "rl:combined:"
	config.KeyGenerator = func(c *fiber.Ctx) string {
		return c.IP() + ":" + c.Path()
	}
	return RateLimit(config)
}
