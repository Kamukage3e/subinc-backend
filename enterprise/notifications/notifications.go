// Package notifications provides a production-grade notification store for SaaS event delivery.
// All implementations must be secure, robust, and ready for real-world deployment.
package notifications

import (
	"context"
	"time"
)

// Notification represents a notification event.
// All fields must be non-sensitive and suitable for audit logging in a SaaS environment.
type Notification struct {
	ID        string     `json:"id" db:"id"`
	Type      string     `json:"type" db:"type"` // email, sms, push, webhook
	Recipient string     `json:"recipient" db:"recipient"`
	Subject   string     `json:"subject" db:"subject"`
	Body      string     `json:"body" db:"body"`
	Status    string     `json:"status" db:"status"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	SentAt    *time.Time `json:"sent_at" db:"sent_at"`
}

// NotificationStore defines storage for notifications.
// All implementations must be production-grade, secure, and ready for SaaS deployment.
type NotificationStore interface {
	// Send must persist and deliver a notification event. Must not leak sensitive info on error.
	Send(ctx context.Context, n *Notification) error
	// GetByID must retrieve a notification by ID. Must return user-friendly errors.
	GetByID(ctx context.Context, id string) (*Notification, error)
	// List must return notifications filtered by recipient/type/status. Must be robust and paginated.
	List(ctx context.Context, recipient, notifType string, status string, limit, offset int) ([]*Notification, error)
	// MarkSent must update notification status and sent timestamp. Must be idempotent and safe.
	MarkSent(ctx context.Context, id string, sentAt time.Time) error
}
