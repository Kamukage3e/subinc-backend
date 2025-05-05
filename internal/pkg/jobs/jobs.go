package jobs

import (
	"context"
	"time"
)

// Priority represents job priority levels
type Priority int

const (
	// PriorityLow is for non-critical background tasks
	PriorityLow Priority = 1

	// PriorityNormal is the default priority for most jobs
	PriorityNormal Priority = 5

	// PriorityHigh is for important jobs that should be processed quickly
	PriorityHigh Priority = 10

	// PriorityCritical is for jobs that require immediate attention
	PriorityCritical Priority = 20
)

// Job represents a background job to be processed
type Job struct {
	// ID is the unique identifier for the job
	ID string `json:"id"`

	// Type is the job type, used to route to the correct handler
	Type string `json:"type"`

	// TenantID is the ID of the tenant this job belongs to
	TenantID string `json:"tenant_id"`

	// Priority determines the processing order (higher = processed sooner)
	Priority Priority `json:"priority"`

	// Payload contains job-specific data
	Payload map[string]interface{} `json:"payload"`

	// MaxRetries is the maximum number of retries for this job
	MaxRetries int `json:"max_retries"`

	// CurrentRetry tracks the current retry count
	CurrentRetry int `json:"current_retry"`

	// ScheduledFor indicates when the job should be processed
	ScheduledFor *time.Time `json:"scheduled_for,omitempty"`

	// CreatedAt is when the job was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the job was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// JobStatus represents the current state of a job
type JobStatus string

const (
	// StatusQueued indicates the job is queued for processing
	StatusQueued JobStatus = "queued"

	// StatusInProgress indicates the job is currently being processed
	StatusInProgress JobStatus = "in_progress"

	// StatusCompleted indicates the job completed successfully
	StatusCompleted JobStatus = "completed"

	// StatusFailed indicates the job failed and will not be retried
	StatusFailed JobStatus = "failed"

	// StatusRetrying indicates the job failed but will be retried
	StatusRetrying JobStatus = "retrying"

	// StatusCancelled indicates the job was cancelled before completion
	StatusCancelled JobStatus = "cancelled"
)

// Queue defines the interface for job queues
type Queue interface {
	// Enqueue adds a job to the queue
	Enqueue(ctx context.Context, job Job) error

	// EnqueueBatch adds multiple jobs to the queue in a single transaction
	EnqueueBatch(ctx context.Context, jobs []Job) error

	// GetJob retrieves a job by ID
	GetJob(ctx context.Context, jobID string) (*Job, error)

	// UpdateJobStatus updates the status of a job
	UpdateJobStatus(ctx context.Context, jobID string, status JobStatus, result map[string]interface{}) error

	// CancelJob cancels a job if it hasn't started processing
	CancelJob(ctx context.Context, jobID string) error

	// ListJobs lists jobs based on filter criteria
	ListJobs(ctx context.Context, tenantID, jobType string, status []JobStatus, page, pageSize int) ([]Job, int, error)
}

// Handler defines the interface for job handlers
type Handler interface {
	// HandleJob processes a job
	HandleJob(ctx context.Context, job Job) error

	// JobType returns the job type this handler can process
	JobType() string
}

// RedisQueue implements Queue using Redis
// This is a placeholder implementation - the actual Redis implementation would be more complex
type RedisQueue struct {
	// Redis client would be here
	// client redis.Client
}

// NewRedisQueue creates a new Redis-backed job queue
func NewRedisQueue() Queue {
	return &RedisQueue{}
}

// Enqueue adds a job to the queue
func (q *RedisQueue) Enqueue(ctx context.Context, job Job) error {
	// This would use Redis to store the job
	// Set defaults if not provided
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	job.UpdatedAt = time.Now().UTC()

	// Implementation details would use Redis commands to add the job to a sorted set
	return nil
}

// EnqueueBatch adds multiple jobs to the queue in a single transaction
func (q *RedisQueue) EnqueueBatch(ctx context.Context, jobs []Job) error {
	// This would use Redis transactions to store multiple jobs
	return nil
}

// GetJob retrieves a job by ID
func (q *RedisQueue) GetJob(ctx context.Context, jobID string) (*Job, error) {
	// This would retrieve the job from Redis
	return nil, nil
}

// UpdateJobStatus updates the status of a job
func (q *RedisQueue) UpdateJobStatus(ctx context.Context, jobID string, status JobStatus, result map[string]interface{}) error {
	// This would update the job status in Redis
	return nil
}

// CancelJob cancels a job if it hasn't started processing
func (q *RedisQueue) CancelJob(ctx context.Context, jobID string) error {
	// This would mark the job as cancelled in Redis
	return nil
}

// ListJobs lists jobs based on filter criteria
func (q *RedisQueue) ListJobs(ctx context.Context, tenantID, jobType string, status []JobStatus, page, pageSize int) ([]Job, int, error) {
	// This would list jobs from Redis based on the provided filters
	return nil, 0, nil
}
