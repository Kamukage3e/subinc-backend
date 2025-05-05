package admin

import (
	"context"
	"time"
)

// ComplianceCheck represents a compliance check result.
type ComplianceCheck struct {
	ID        string    `json:"id" db:"id"`
	Type      string    `json:"type" db:"type"` // e.g., SOC2, ISO, CIS
	Status    string    `json:"status" db:"status"`
	Details   string    `json:"details" db:"details"`
	CheckedAt time.Time `json:"checked_at" db:"checked_at"`
}

// ComplianceStore defines storage for compliance checks and reports.
type ComplianceStore interface {
	RunCheck(ctx context.Context, checkType string) (*ComplianceCheck, error)
	ListChecks(ctx context.Context, checkType string, limit, offset int) ([]*ComplianceCheck, error)
	ExportReport(ctx context.Context, checkType string) ([]byte, error)
}
