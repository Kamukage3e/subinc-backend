# Package Directory (pkg)

This directory contains shared, reusable packages for the Subinc Cost Management Microservice.

## Core Packages

### Cache (`pkg/cache`)

A production-grade Redis-backed caching system with:

- TTL support for automatic expiration
- JSON serialization for complex objects
- Strong error handling with custom error types
- Comprehensive metrics for Prometheus
- Structured logging with Zap
- Batched operations for better performance
- Atomic operations like SetWithLock

```go
// Example usage:
cacheService := cache.NewRedisCache(redisClient, logger, "app:cache")
err := cacheService.Set(ctx, "user:profile:123", userProfile, 24*time.Hour)
```

### Session (`pkg/session`)

A secure Redis-backed session manager with:

- Secure, random session ID generation
- CSRF protection
- Session rotation for security
- Automatic expiration and cleanup
- Queryable by user, tenant, or ID
- Prometheus metrics for active sessions
- Size limits to prevent abuse

```go
// Example usage:
sessionMgr := session.NewSessionManager(redisClient, logger, "app:session")
session, err := sessionMgr.Create(ctx, userId, tenantId, sessionData)
```

### Background Jobs (`pkg/jobs`)

A Redis-backed job queue system with Asynq:

- Prioritized job queues
- Job scheduling with cron syntax
- Delayed jobs and retries with backoff
- Comprehensive metrics and monitoring
- Graceful shutdown support
- Task handlers with dependency injection
- Automatic job cleanup

```go
// Example usage:
jobClient := jobs.NewBackgroundJobClient(redisClient, logger)
jobId, err := jobClient.Enqueue(jobs.TaskSyncAWSCost, payload, jobs.WithHighPriority()...)
```

## Design Principles

All packages follow these principles:

1. **Robustness**: All operations have proper error handling and recovery
2. **Observability**: Comprehensive metrics, logging, and tracing
3. **Security**: Secure defaults and protection against common attacks
4. **Performance**: Efficient operations, connection pooling, and pipelining
5. **Configurability**: Customizable options with sensible defaults

## Production Features

All Redis-backed components include:

- Connection pooling and reuse
- Circuit breakers for resilience
- Comprehensive metrics and monitoring
- Structured logging with proper levels
- Graceful handling of Redis failures
- Automatic reconnection and recovery
- Proper cleanup of resources

## Metrics

All components export Prometheus metrics for:

- Operation latency (histograms)
- Success/failure rates (counters)
- Resource utilization (gauges)
- Error types and frequencies (counters)
- Queue sizes and processing rates (gauges)

## Error Handling

All components use custom error types for precise error handling:

- Specific error types for different failure modes
- Context-aware errors with wrapped causes
- Clear error messages for debugging
- Non-exposing errors for security

## Configuration

All components can be configured via environment variables or Viper:

- Connection parameters
- Timeouts and retries
- Prefix namespaces
- Performance tuning
- Security options 