package auditutil

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
)

// getActorID extracts the user/actor ID from the context (customize as needed)
func getActorID(c *fiber.Ctx) string {
	id, _ := c.Locals("user_id").(string)
	return id
}

// getResourceAndID tries to extract resource and resourceID from route or params
func getResourceAndID(c *fiber.Ctx) (string, string) {
	params := c.AllParams()
	resource := ""
	resourceID := ""
	if len(params) > 0 {
		for k, v := range params {
			if k == "id" || k == "resource_id" || k == "policy_id" {
				resourceID = v
			}
		}
	}
	// crude resource extraction: first path segment after /
	parts := c.Route().Path
	if len(parts) > 1 {
		resource = parts[1:]
	}
	return resource, resourceID
}

// AuditLoggerMiddleware logs every request using the provided security_management.AuditLogger.
func AuditLoggerMiddleware(logger security_management.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)
		userID := getActorID(c)
		status := c.Response().StatusCode()
		event := c.Method() + " " + c.Path()
		resource, resourceID := getResourceAndID(c)
		ip := c.IP()
		userAgent := c.Get("User-Agent")
		metadata := map[string]interface{}{
			"status":     status,
			"latency_ms": latency.Milliseconds(),
		}
		if c.Body() != nil && len(c.Body()) > 0 {
			metadata["body"] = string(c.Body())
		}
		metadataJSON, _ := json.Marshal(metadata)
		log := security_management.SecurityAuditLog{
			ID:         uuid.NewString(),
			UserID:     userID,
			ActorID:    userID,
			Action:     event,
			Resource:   resource,
			ResourceID: resourceID,
			IP:         ip,
			UserAgent:  userAgent,
			CreatedAt:  time.Now().UTC(),
			Details:    string(metadataJSON),
		}
		_, _ = logger.CreateSecurityAuditLog(context.Background(), log)
		return err
	}
}
