package domain

import (
	"time"
)

// WebhookEvent represents a webhook event from a payment provider
// All fields are required for SaaS billing and auditability
// Status: received, processed, failed
// Metadata: JSON-encoded for extensibility

type WebhookEvent struct {
	ID          string     `json:"id"`
	Provider    string     `json:"provider"`
	EventType   string     `json:"event_type"`
	Payload     string     `json:"payload"`
	Status      string     `json:"status"`
	ReceivedAt  time.Time  `json:"received_at"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Metadata    string     `json:"metadata"`
}

func (w *WebhookEvent) Validate() error {
	if w.Provider == "" {
		return NewValidationError("provider", "must not be empty")
	}
	if w.EventType == "" {
		return NewValidationError("event_type", "must not be empty")
	}
	if w.Payload == "" {
		return NewValidationError("payload", "must not be empty")
	}
	if w.Status != "received" && w.Status != "processed" && w.Status != "failed" {
		return NewValidationError("status", "must be 'received', 'processed', or 'failed'")
	}
	if w.ReceivedAt.IsZero() {
		return NewValidationError("received_at", "must not be zero")
	}
	return nil
}
