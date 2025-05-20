package auditutil

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// AuditLog represents a simplified security audit log entry to avoid import cycles
type AuditLog struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	ActorID    string                 `json:"actor_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID string                 `json:"resource_id"`
	IP         string                 `json:"ip"`
	UserAgent  string                 `json:"user_agent"`
	CreatedAt  time.Time              `json:"created_at"`
	Details    string                 `json:"details"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// AuditLogger defines a simplified interface for audit logging to avoid import cycles
type AuditLogger interface {
	// CreateAuditLog creates an audit log entry
	CreateAuditLog(ctx context.Context, log AuditLog) (AuditLog, error)
}

var (
	globalAuditLogger AuditLogger
	initOnce          sync.Once
)

// InitGlobalAuditLogger initializes the global audit logger
func InitGlobalAuditLogger(auditLogger AuditLogger) {
	initOnce.Do(func() {
		globalAuditLogger = auditLogger
		if auditLogger != nil {
			// Log initialization through the application logger
			logger.LogInfo("Global audit logger initialized")
		}
	})
}

// GetGlobalAuditLogger returns the global audit logger
func GetGlobalAuditLogger() (AuditLogger, error) {
	if globalAuditLogger == nil {
		err := fmt.Errorf("GlobalAuditLogger not initialized")
		logger.LogError("GetGlobalAuditLogger", logger.ErrorField(err))
		return nil, err
	}
	return globalAuditLogger, nil
}
