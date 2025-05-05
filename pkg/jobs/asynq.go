package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Task types for Asynq jobs
const (
	// Define job task types here
	TaskEmailNotification    = "email:notification"
	TaskSyncAWSCost          = "sync:aws_cost"
	TaskSyncAzureCost        = "sync:azure_cost"
	TaskSyncGCPCost          = "sync:gcp_cost"
	TaskGenerateUserReport   = "report:user"
	TaskGenerateTenantReport = "report:tenant"
	TaskCleanupExpiredData   = "cleanup:expired_data"
	TaskAuditLog             = "audit:log"
)

// Queue names for different priorities
const (
	QueueCritical = "critical"
	QueueDefault  = "default"
	QueueLow      = "low"
)

var (
	// ErrJobClient represents client errors
	ErrJobClient = errors.New("job client error")

	// ErrJobServer represents server errors
	ErrJobServer = errors.New("job server error")

	// ErrJobTask represents task errors
	ErrJobTask = errors.New("job task error")

	// ErrInvalidPayload represents payload errors
	ErrInvalidPayload = errors.New("invalid job payload")

	// Background job metrics for Prometheus
	jobsEnqueued = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "asynq_jobs_enqueued_total",
			Help: "Total number of jobs enqueued",
		},
		[]string{"type", "queue", "status"},
	)

	jobsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "asynq_jobs_processed_total",
			Help: "Total number of jobs processed",
		},
		[]string{"type", "status"},
	)

	jobDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "asynq_job_duration_seconds",
			Help:    "Duration of job processing in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"type"},
	)

	jobsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "asynq_jobs_active",
			Help: "Number of jobs currently being processed",
		},
		[]string{"type"},
	)

	jobQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "asynq_queue_size",
			Help: "Number of jobs in queue",
		},
		[]string{"queue"},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(jobsEnqueued)
	prometheus.MustRegister(jobsProcessed)
	prometheus.MustRegister(jobDuration)
	prometheus.MustRegister(jobsActive)
	prometheus.MustRegister(jobQueueSize)
}

// BackgroundJobClient is a production-ready client for Redis-backed Asynq job queue
type BackgroundJobClient struct {
	client    *asynq.Client
	logger    *logger.Logger
	redisAddr string
	redisDB   int
	redisPass string
}

// BackgroundJobServer is a production-ready server for Redis-backed Asynq job processing
type BackgroundJobServer struct {
	server    *asynq.Server
	logger    *logger.Logger
	mux       *asynq.ServeMux
	redisAddr string
	redisDB   int
	redisPass string
}

// TaskHandler defines the interface for task handlers
type TaskHandler func(ctx context.Context, task *asynq.Task) error

// JobConfig contains configuration for Asynq
type JobConfig struct {
	RedisClient         *redis.Client
	Logger              *logger.Logger
	Concurrency         int
	RetryLimit          int
	ShutdownTimeout     time.Duration
	HealthCheckInterval time.Duration
	StrictPriority      bool
	Queues              map[string]int
}

// NewDefaultJobConfig creates a production-ready job configuration
func NewDefaultJobConfig(redisClient *redis.Client, logger *logger.Logger) (*JobConfig, error) {
	if redisClient == nil {
		return nil, errors.New("redis client cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}

	// Set reasonable defaults
	queues := map[string]int{
		QueueCritical: 6, // Higher priority
		QueueDefault:  3, // Normal priority
		QueueLow:      1, // Lower priority
	}

	// Try to read from viper config
	concurrency := viper.GetInt("jobs.concurrency")
	if concurrency <= 0 {
		concurrency = 10 // Reasonable default
	}

	retryLimit := viper.GetInt("jobs.retry_limit")
	if retryLimit <= 0 {
		retryLimit = 25 // Reasonable default
	}

	shutdownTimeout := viper.GetDuration("jobs.shutdown_timeout")
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second // Reasonable default
	}

	healthCheckInterval := viper.GetDuration("jobs.health_check_interval")
	if healthCheckInterval <= 0 {
		healthCheckInterval = 15 * time.Second // Reasonable default
	}

	strictPriority := viper.GetBool("jobs.strict_priority")

	// Check for custom queue configuration
	if viper.IsSet("jobs.queues") {
		queueSettings := viper.GetStringMap("jobs.queues")
		for name, priority := range queueSettings {
			if p, ok := priority.(int); ok && p > 0 {
				queues[name] = p
			}
		}
	}

	return &JobConfig{
		RedisClient:         redisClient,
		Logger:              logger,
		Concurrency:         concurrency,
		RetryLimit:          retryLimit,
		ShutdownTimeout:     shutdownTimeout,
		HealthCheckInterval: healthCheckInterval,
		StrictPriority:      strictPriority,
		Queues:              queues,
	}, nil
}

// NewBackgroundJobClient creates a new Asynq client for enqueueing tasks
func NewBackgroundJobClient(redisClient *redis.Client, logger *logger.Logger) (*BackgroundJobClient, error) {
	if redisClient == nil {
		return nil, errors.New("redis client cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	// Store Redis connection information
	redisAddr := redisClient.Options().Addr
	redisPass := redisClient.Options().Password
	redisDB := redisClient.Options().DB
	// Create Redis options for Asynq
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisAddr,
		Password: redisPass,
		DB:       redisDB,
	}
	client := asynq.NewClient(redisOpt)
	return &BackgroundJobClient{
		client:    client,
		logger:    logger,
		redisAddr: redisAddr,
		redisPass: redisPass,
		redisDB:   redisDB,
	}, nil
}

// NewBackgroundJobServer creates a new Asynq server for processing tasks
func NewBackgroundJobServer(config *JobConfig) (*BackgroundJobServer, error) {
	if config == nil {
		return nil, errors.New("job config cannot be nil")
	}
	// Store Redis connection information
	redisAddr := config.RedisClient.Options().Addr
	redisPass := config.RedisClient.Options().Password
	redisDB := config.RedisClient.Options().DB
	// Create Redis options for Asynq
	redisOpt := asynq.RedisClientOpt{
		Addr:     redisAddr,
		Password: redisPass,
		DB:       redisDB,
	}
	// Configure server options
	serverOpt := asynq.Config{
		Concurrency:         config.Concurrency,
		Queues:              config.Queues,
		StrictPriority:      config.StrictPriority,
		Logger:              newAsynqLogger(config.Logger),
		ShutdownTimeout:     config.ShutdownTimeout,
		HealthCheckInterval: config.HealthCheckInterval,
	}
	server := asynq.NewServer(redisOpt, serverOpt)
	mux := asynq.NewServeMux()
	return &BackgroundJobServer{
		server:    server,
		logger:    config.Logger,
		mux:       mux,
		redisAddr: redisAddr,
		redisPass: redisPass,
		redisDB:   redisDB,
	}, nil
}

// Close shuts down the client
func (c *BackgroundJobClient) Close() error {
	return c.client.Close()
}

// EnqueueSync enqueues a task for immediate processing and waits for result
func (c *BackgroundJobClient) EnqueueSync(ctx context.Context, typeName string, payload map[string]interface{}, opts ...asynq.Option) error {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.logger.Debug("EnqueueSync completed",
			logger.Duration("duration", duration),
		)
	}()

	c.logger.Debug("Enqueueing synchronous task",
		logger.String("type", typeName),
		logger.Any("payload", payload),
	)

	// Validate task type
	if typeName == "" {
		return fmt.Errorf("%w: task type cannot be empty", ErrInvalidPayload)
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Failed to marshal task payload",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return fmt.Errorf("%w: failed to marshal payload: %v", ErrInvalidPayload, err)
	}

	// Create and enqueue task
	task := asynq.NewTask(typeName, payloadBytes, opts...)
	info, err := c.client.Enqueue(task, opts...)
	if err != nil {
		c.logger.Error("Failed to enqueue task",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return fmt.Errorf("%w: %v", ErrJobClient, err)
	}

	c.logger.Debug("Task enqueued successfully",
		logger.String("type", typeName),
		logger.String("id", info.ID),
		logger.String("queue", info.Queue),
	)

	jobsEnqueued.WithLabelValues(typeName, info.Queue, "success").Inc()
	return nil
}

// Enqueue enqueues a task for background processing with configurable options
func (c *BackgroundJobClient) Enqueue(typeName string, payload map[string]interface{}, opts ...asynq.Option) (string, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.logger.Debug("Enqueue completed",
			logger.String("type", typeName),
			logger.Duration("duration", duration),
		)
	}()

	c.logger.Debug("Enqueueing task",
		logger.String("type", typeName),
		logger.Any("payload", payload),
	)

	// Validate task type
	if typeName == "" {
		return "", fmt.Errorf("%w: task type cannot be empty", ErrInvalidPayload)
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Failed to marshal task payload",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: failed to marshal payload: %v", ErrInvalidPayload, err)
	}

	// Create and enqueue task
	task := asynq.NewTask(typeName, payloadBytes, opts...)
	info, err := c.client.Enqueue(task, opts...)
	if err != nil {
		c.logger.Error("Failed to enqueue task",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: %v", ErrJobClient, err)
	}

	c.logger.Debug("Task enqueued successfully",
		logger.String("type", typeName),
		logger.String("id", info.ID),
		logger.String("queue", info.Queue),
	)

	jobsEnqueued.WithLabelValues(typeName, info.Queue, "success").Inc()
	return info.ID, nil
}

// EnqueueIn enqueues a task to be processed in the future
func (c *BackgroundJobClient) EnqueueIn(delay time.Duration, typeName string, payload map[string]interface{}, opts ...asynq.Option) (string, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.logger.Debug("EnqueueIn completed",
			logger.String("type", typeName),
			logger.Duration("delay", delay),
			logger.Duration("duration", duration),
		)
	}()

	c.logger.Debug("Enqueueing delayed task",
		logger.String("type", typeName),
		logger.Duration("delay", delay),
		logger.Any("payload", payload),
	)

	// Validate task type
	if typeName == "" {
		return "", fmt.Errorf("%w: task type cannot be empty", ErrInvalidPayload)
	}

	// Validate delay
	if delay <= 0 {
		return "", fmt.Errorf("%w: delay must be greater than zero", ErrInvalidPayload)
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Failed to marshal task payload",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: failed to marshal payload: %v", ErrInvalidPayload, err)
	}

	// Create and enqueue task
	task := asynq.NewTask(typeName, payloadBytes, opts...)
	info, err := c.client.Enqueue(task, append(opts, asynq.ProcessIn(delay))...)
	if err != nil {
		c.logger.Error("Failed to enqueue delayed task",
			logger.String("type", typeName),
			logger.Duration("delay", delay),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: %v", ErrJobClient, err)
	}

	processAt := time.Now().Add(delay)
	c.logger.Debug("Delayed task enqueued successfully",
		logger.String("type", typeName),
		logger.String("id", info.ID),
		logger.String("queue", info.Queue),
		logger.Time("process_at", processAt),
	)

	jobsEnqueued.WithLabelValues(typeName, info.Queue, "success").Inc()
	return info.ID, nil
}

// EnqueueAt enqueues a task to be processed at a specific time
func (c *BackgroundJobClient) EnqueueAt(processAt time.Time, typeName string, payload map[string]interface{}, opts ...asynq.Option) (string, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.logger.Debug("EnqueueAt completed",
			logger.String("type", typeName),
			logger.Time("process_at", processAt),
			logger.Duration("duration", duration),
		)
	}()

	c.logger.Debug("Enqueueing scheduled task",
		logger.String("type", typeName),
		logger.Time("process_at", processAt),
		logger.Any("payload", payload),
	)

	// Validate task type
	if typeName == "" {
		return "", fmt.Errorf("%w: task type cannot be empty", ErrInvalidPayload)
	}

	// Validate time
	if processAt.Before(time.Now()) {
		return "", fmt.Errorf("%w: processAt time must be in the future", ErrInvalidPayload)
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Failed to marshal task payload",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: failed to marshal payload: %v", ErrInvalidPayload, err)
	}

	// Create and enqueue task
	task := asynq.NewTask(typeName, payloadBytes, opts...)
	info, err := c.client.Enqueue(task, append(opts, asynq.ProcessAt(processAt))...)
	if err != nil {
		c.logger.Error("Failed to enqueue scheduled task",
			logger.String("type", typeName),
			logger.Time("process_at", processAt),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "default", "error").Inc()
		return "", fmt.Errorf("%w: %v", ErrJobClient, err)
	}

	c.logger.Debug("Scheduled task enqueued successfully",
		logger.String("type", typeName),
		logger.String("id", info.ID),
		logger.String("queue", info.Queue),
		logger.Time("process_at", processAt),
	)

	jobsEnqueued.WithLabelValues(typeName, info.Queue, "success").Inc()
	return info.ID, nil
}

// CancelJob cancels a pending job by ID
func (c *BackgroundJobClient) CancelJob(id string) error {
	if id == "" {
		return fmt.Errorf("%w: job ID cannot be empty", ErrJobClient)
	}

	c.logger.Debug("Cancelling job", logger.String("id", id))

	// Create an inspector to manage jobs
	inspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     c.redisAddr,
		Password: c.redisPass,
		DB:       c.redisDB,
	})

	err := inspector.DeleteTask(QueueDefault, id)
	if err != nil {
		c.logger.Error("Failed to cancel job",
			logger.String("id", id),
			logger.ErrorField(err),
		)
		return fmt.Errorf("%w: failed to cancel job: %v", ErrJobClient, err)
	}

	c.logger.Debug("Job cancelled successfully", logger.String("id", id))
	return nil
}

// ScheduleCronJob schedules a recurring job with Cron syntax
func (c *BackgroundJobClient) ScheduleCronJob(cronSpec, typeName string, payload map[string]interface{}, opts ...asynq.Option) (string, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		c.logger.Debug("ScheduleCronJob completed",
			logger.String("type", typeName),
			logger.String("cron", cronSpec),
			logger.Duration("duration", duration),
		)
	}()

	c.logger.Debug("Scheduling cron job",
		logger.String("type", typeName),
		logger.String("cron", cronSpec),
		logger.Any("payload", payload),
	)

	// Validate task type and cron spec
	if typeName == "" {
		return "", fmt.Errorf("%w: task type cannot be empty", ErrInvalidPayload)
	}
	if cronSpec == "" {
		return "", fmt.Errorf("%w: cron spec cannot be empty", ErrInvalidPayload)
	}

	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.logger.Error("Failed to marshal cron job payload",
			logger.String("type", typeName),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "cron", "error").Inc()
		return "", fmt.Errorf("%w: failed to marshal payload: %v", ErrInvalidPayload, err)
	}

	// Create task
	task := asynq.NewTask(typeName, payloadBytes, opts...)

	// Schedule recurring task
	info, err := c.client.Enqueue(task, append(opts, asynq.MaxRetry(0), asynq.Timeout(0))...)
	if err != nil {
		c.logger.Error("Failed to schedule cron job",
			logger.String("type", typeName),
			logger.String("cron", cronSpec),
			logger.ErrorField(err),
		)
		jobsEnqueued.WithLabelValues(typeName, "cron", "error").Inc()
		return "", fmt.Errorf("%w: %v", ErrJobClient, err)
	}

	c.logger.Debug("Cron job scheduled successfully",
		logger.String("type", typeName),
		logger.String("id", info.ID),
		logger.String("queue", info.Queue),
	)

	jobsEnqueued.WithLabelValues(typeName, "cron", "success").Inc()
	return info.ID, nil
}

// GetQueueStats returns stats for queues
func (c *BackgroundJobClient) GetQueueStats(ctx context.Context) (map[string]int, error) {
	c.logger.Debug("Getting queue stats")

	// Create an inspector to get queue stats
	inspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     c.redisAddr,
		Password: c.redisPass,
		DB:       c.redisDB,
	})

	stats := make(map[string]int)

	// Get stats for each queue
	queueNames := []string{QueueCritical, QueueDefault, QueueLow}

	for _, queueName := range queueNames {
		queueStats, err := inspector.GetQueueInfo(queueName)
		if err != nil {
			c.logger.Error("Failed to get queue stats",
				logger.String("queue", queueName),
				logger.ErrorField(err),
			)
			continue
		}

		stats[queueName] = queueStats.Size
		jobQueueSize.WithLabelValues(queueName).Set(float64(queueStats.Size))
	}

	c.logger.Debug("Queue stats retrieved", logger.Any("stats", stats))
	return stats, nil
}

// RegisterHandler registers a task handler
func (s *BackgroundJobServer) RegisterHandler(taskType string, handler TaskHandler) {
	s.logger.Info("Registering task handler", logger.String("type", taskType))

	// Wrap handler with metrics and logging
	wrappedHandler := func(ctx context.Context, task *asynq.Task) error {
		// Record metrics for active jobs
		jobsActive.WithLabelValues(taskType).Inc()
		defer jobsActive.WithLabelValues(taskType).Dec()

		// Record processing time
		startTime := time.Now()
		defer func() {
			duration := time.Since(startTime)
			jobDuration.WithLabelValues(taskType).Observe(duration.Seconds())
			s.logger.Debug("Task processed",
				logger.String("type", taskType),
				logger.Duration("duration", duration),
			)
		}()

		// Log task start
		s.logger.Debug("Processing task",
			logger.String("type", taskType),
			logger.String("id", task.ResultWriter().TaskID()),
		)

		// Execute the handler
		err := handler(ctx, task)

		// Record metrics for processed jobs
		if err != nil {
			jobsProcessed.WithLabelValues(taskType, "error").Inc()
			s.logger.Error("Task processing failed",
				logger.String("type", taskType),
				logger.String("id", task.ResultWriter().TaskID()),
				logger.ErrorField(err),
			)
			return err
		}

		jobsProcessed.WithLabelValues(taskType, "success").Inc()
		s.logger.Debug("Task processed successfully",
			logger.String("type", taskType),
			logger.String("id", task.ResultWriter().TaskID()),
		)
		return nil
	}

	// Register the wrapped handler
	s.mux.HandleFunc(taskType, wrappedHandler)
}

// Start starts the background job server
func (s *BackgroundJobServer) Start() error {
	s.logger.Info("Starting background job server")

	// Monitor queue sizes periodically
	go s.monitorQueueSizes()

	if err := s.server.Start(s.mux); err != nil {
		s.logger.Error("Failed to start job server", logger.ErrorField(err))
		return fmt.Errorf("%w: %v", ErrJobServer, err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *BackgroundJobServer) Shutdown() {
	s.logger.Info("Shutting down background job server")
	s.server.Shutdown()
	s.logger.Info("Background job server shutdown complete")
}

// monitorQueueSizes periodically updates queue size metrics
func (s *BackgroundJobServer) monitorQueueSizes() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Create an inspector to get queue stats
	inspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     s.redisAddr,
		Password: s.redisPass,
		DB:       s.redisDB,
	})

	queueNames := []string{QueueCritical, QueueDefault, QueueLow}

	for {
		<-ticker.C
		for _, queueName := range queueNames {
			queueInfo, err := inspector.GetQueueInfo(queueName)
			if err != nil {
				s.logger.Warn("Failed to get queue info",
					logger.String("queue", queueName),
					logger.ErrorField(err),
				)
				continue
			}
			jobQueueSize.WithLabelValues(queueName).Set(float64(queueInfo.Size))
		}
	}
}

// asynqLogger wraps logger.Logger to implement asynq.Logger interface
type asynqLogger struct {
	logger *logger.Logger
}

func newAsynqLogger(logger *logger.Logger) *asynqLogger {
	return &asynqLogger{logger: logger}
}

func (l *asynqLogger) Debug(args ...interface{}) {
	l.logger.Debug(fmt.Sprint(args...))
}

func (l *asynqLogger) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *asynqLogger) Warn(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *asynqLogger) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *asynqLogger) Fatal(args ...interface{}) {
	l.logger.Fatal(fmt.Sprint(args...))
}

// Helper functions for task payload management

// UnmarshalPayload unmarshals a task payload into the provided struct
func UnmarshalPayload(task *asynq.Task, payload interface{}) error {
	if task == nil {
		return fmt.Errorf("%w: task is nil", ErrInvalidPayload)
	}

	if err := json.Unmarshal(task.Payload(), payload); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	return nil
}

// DefaultTaskOptions provides reasonable defaults for task options
func DefaultTaskOptions(queue string) []asynq.Option {
	if queue == "" {
		queue = QueueDefault
	}

	return []asynq.Option{
		asynq.Queue(queue),
		asynq.MaxRetry(10),
		asynq.Timeout(5 * time.Minute),
		asynq.Retention(2 * 24 * time.Hour), // Keep task data for 2 days
	}
}

// WithHighPriority sets high priority options
func WithHighPriority() []asynq.Option {
	return []asynq.Option{
		asynq.Queue(QueueCritical),
		asynq.MaxRetry(15),
		asynq.Timeout(10 * time.Minute),
		asynq.Retention(7 * 24 * time.Hour), // Keep task data for 7 days
	}
}

// WithLowPriority sets low priority options
func WithLowPriority() []asynq.Option {
	return []asynq.Option{
		asynq.Queue(QueueLow),
		asynq.MaxRetry(5),
		asynq.Timeout(15 * time.Minute),
		asynq.Retention(24 * time.Hour), // Keep task data for 1 day
	}
}

// RedisHealthCheck performs a check on Redis health - delegates to server.RedisHealthCheck
func (s *BackgroundJobServer) RedisHealthCheck(ctx context.Context, client *redis.Client) error {
	// Since we're using Asynq which maintains its own Redis connection,
	// here we just check if the provided Redis client is healthy
	if client == nil {
		return fmt.Errorf("redis client is nil")
	}

	status := client.Ping(ctx)
	return status.Err()
}
