package commonutil

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// MarshalAuditDetails serializes any value to JSON string for audit logs
func MarshalAuditDetails(v interface{}) string {
	// Handle string input directly
	if s, ok := v.(string); ok {
		return s
	}

	b, err := json.Marshal(v)
	if err != nil {
		logger.LogError("failed to marshal audit details", logger.ErrorField(err))
		return "{}"
	}
	return string(b)
}

// GetActorID extracts the actor ID from Fiber context headers
// Returns empty string if not found (never returns "system" by default)
func GetActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}

// GetTenantID extracts the tenant ID from Fiber context
// Checks headers, query params, and request body
func GetTenantID(c *fiber.Ctx) string {
	tid := c.Get("X-Tenant-ID")
	if tid != "" {
		return tid
	}
	if v := c.Query("tenant_id"); v != "" {
		return v
	}
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	_ = c.BodyParser(&body)
	if body.TenantID != "" {
		return body.TenantID
	}
	return ""
}

// GetActorOrSystem returns the actor ID or "system" if not present
// This is useful for automated processes that need to record an actor
func GetActorOrSystem(c *fiber.Ctx) string {
	id := GetActorID(c)
	if id == "" {
		return "system"
	}
	return id
}

// NowUTC returns the current time in UTC
// Consistent time format for all audit log events
func NowUTC() time.Time {
	return time.Now().UTC()
}
