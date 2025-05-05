package admin

import (
	"context"
	"time"
)

// AuditLog represents an immutable, tamper-evident audit log entry.
type AuditLog struct {
	ID        string    `json:"id" db:"id"`
	ActorID   string    `json:"actor_id" db:"actor_id"`
	Action    string    `json:"action" db:"action"`
	Resource  string    `json:"resource" db:"resource"`
	Details   string    `json:"details" db:"details"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Hash      string    `json:"hash" db:"hash"`
	PrevHash  string    `json:"prev_hash" db:"prev_hash"`
}

// AuditLogStore defines storage for audit logs.
type AuditLogStore interface {
	Append(ctx context.Context, log *AuditLog) error
	List(ctx context.Context, resource string, limit, offset int) ([]*AuditLog, error)
	GetByID(ctx context.Context, id string) (*AuditLog, error)
}
