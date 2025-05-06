package server

import (
	"time"


	"github.com/subinc/subinc-backend/internal/pkg/logger"

)

// Use custom type for context keys to avoid collisions
type redisContextKey string

// RedisConfig contains all Redis configuration parameters
type RedisConfig struct {
	URL             string
	Host            string
	Port            string
	Password        string
	DB              int
	MaxRetries      int
	MinIdleConns    int
	PoolSize        int
	PoolTimeout     time.Duration
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ConnMaxIdleTime time.Duration
	ConnMaxLifetime time.Duration
}

// RedisHook implements redis.Hook for metrics and logging
type RedisHook struct {
	logger *logger.Logger
}

