package server

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrRedisConnection represents Redis connection failures
	ErrRedisConnection = errors.New("failed to connect to Redis")

	// ErrRedisOperation represents Redis operation failures
	ErrRedisOperation = errors.New("Redis operation failed")

	// Redis metrics for Prometheus
	redisOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "redis_operations_total",
			Help: "Total number of Redis operations",
		},
		[]string{"operation", "status"},
	)

	redisOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "redis_operation_duration_seconds",
			Help:    "Duration of Redis operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	redisConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "redis_connections_active",
			Help: "Number of active Redis connections",
		},
	)
)
