package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: []float64{0.001, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "Size of HTTP responses in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "path"},
	)
)

var (
	// Prometheus metrics for rate limiting
	rateLimitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rate_limit_requests_total",
			Help: "Total number of requests checked by rate limiter",
		},
		[]string{"status"},
	)

	rateLimitRemaining = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rate_limit_remaining",
			Help:    "Remaining requests in rate limit window",
			Buckets: []float64{0, 1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
		[]string{"ip_class"},
	)

	rateLimitErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "rate_limit_errors_total",
			Help: "Total number of errors encountered by rate limiter",
		},
	)
)

// RateLimiterConfig represents the rate limiter configuration
type RateLimiterConfig struct {
	// Redis client for distributed rate limiting
	RedisClient *redis.Client

	// Logger for errors and debugging
	Logger *logger.Logger

	// MaxRequests is the maximum number of requests allowed within the window
	MaxRequests int

	// Window is the time window for rate limiting (e.g., 1 minute)
	Window time.Duration

	// KeyPrefix is prepended to all Redis keys
	KeyPrefix string

	// KeyGenerator generates a rate limit key from the request
	// Default: IP-based rate limiting
	KeyGenerator func(c *fiber.Ctx) string

	// LimitReachedHandler is called when rate limit is exceeded
	// Default: Returns 429 Too Many Requests
	LimitReachedHandler fiber.Handler

	// SkipFunc determines if rate limiting should be skipped
	// Default: No skipping
	SkipFunc func(c *fiber.Ctx) bool

	// Headers determines if rate limit headers should be added to responses
	Headers bool
}

// RateLimiterStore is the Redis-backed store for rate limiting
type RateLimiterStore struct {
	client    *redis.Client
	keyPrefix string
	logger    *logger.Logger
}
