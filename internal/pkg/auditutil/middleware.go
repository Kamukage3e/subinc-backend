package auditutil

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"

	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
)

// AuditLoggerMiddleware logs all mutating requests for security and compliance.
func AuditLoggerMiddleware(auditLogger security_management.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := context.WithValue(c.UserContext(), "auditLogger", auditLogger)
		c.SetUserContext(ctx)
		err := c.Next()

		method := c.Method()
		if method == fiber.MethodPost || method == fiber.MethodPut || method == fiber.MethodDelete {
			route := c.Route().Path
			actorID := commonutil.GetActorID(c)
			var details map[string]interface{}
			var targetID string
			if c.Body() != nil && len(c.Body()) > 0 {
				if err := json.Unmarshal(c.Body(), &details); err != nil {
					details = map[string]interface{}{"body": string(c.Body())}
				} else {
					if id, ok := details["id"].(string); ok {
						targetID = id
					} else if tid, ok := details["target_id"].(string); ok {
						targetID = tid
					} else if aid, ok := details["account_id"].(string); ok {
						targetID = aid
					} else if rid, ok := details["req"].(map[string]interface{}); ok {
						if ridVal, ok := rid["ID"].(string); ok {
							targetID = ridVal
						}
					}
				}
			} else {
				details = map[string]interface{}{}
			}
			auditLog := security_management.SecurityAuditLog{
				ID:        uuid.NewString(),
				ActorID:   actorID,
				Action:    route + ":" + method,
				TargetID:  targetID,
				Details:   AuditDetails(details),
				CreatedAt: time.Now().UTC(),
			}
			_, _ = auditLogger.CreateSecurityAuditLog(ctx, auditLog)
		}
		return err
	}
}
