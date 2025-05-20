package auditutil

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	applogger "github.com/subinc/subinc-backend/internal/pkg/logger"
)

// getActorID extracts the user/actor ID from the context (customize as needed)
func getActorID(c *fiber.Ctx) string {
	id, _ := c.Locals("user_id").(string)
	return id
}

// getTenantID extracts the tenant ID from the context if available
func getTenantID(c *fiber.Ctx) string {
	id, _ := c.Locals("tenant_id").(string)
	return id
}

// getResourceAndID tries to extract resource and resourceID from route or params
func getResourceAndID(c *fiber.Ctx) (string, string) {
	params := c.AllParams()
	resource := ""
	resourceID := ""
	if len(params) > 0 {
		for k, v := range params {
			if k == "id" || k == "resource_id" || k == "policy_id" || k == "tenant_id" {
				resourceID = v
			}
		}
	}

	// Extract resource from path
	segments := c.Route().Params
	if len(segments) > 0 {
		resource = segments[0]
	} else {
		// Fallback to first path segment
		parts := c.Route().Path
		if len(parts) > 1 {
			resource = parts[1:]
		}
	}

	return resource, resourceID
}

// getSanitizedBody returns a sanitized version of the request body
// Removes sensitive fields like passwords, tokens, etc.
func getSanitizedBody(c *fiber.Ctx) map[string]interface{} {
	if c.Body() == nil || len(c.Body()) == 0 {
		return nil
	}

	var body map[string]interface{}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return map[string]interface{}{"_raw": string(c.Body())}
	}

	// Remove sensitive fields
	sensitiveFields := []string{
		"password", "token", "secret", "key", "credential",
		"auth", "jwt", "apiKey", "api_key", "credit_card",
	}

	for _, field := range sensitiveFields {
		delete(body, field)
		// Also check nested fields
		for k, v := range body {
			if nestedMap, ok := v.(map[string]interface{}); ok {
				delete(nestedMap, field)
				body[k] = nestedMap
			}
		}
	}

	return body
}

// AuditLoggerMiddleware logs every request using the global audit logger.
// If a specific logger is provided, it will use that instead.
func AuditLoggerMiddleware(customLogger AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Generate request ID if not already set
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
			c.Set("X-Request-ID", requestID)
		}

		start := time.Now()
		err := c.Next()
		latency := time.Since(start)

		// Get all contextual data
		userID := getActorID(c)
		tenantID := getTenantID(c)
		status := c.Response().StatusCode()
		action := c.Method()
		resource, resourceID := getResourceAndID(c)
		ip := c.IP()
		userAgent := c.Get("User-Agent")

		// Build metadata with comprehensive request details
		metadata := map[string]interface{}{
			"request_id":      requestID,
			"tenant_id":       tenantID,
			"status":          status,
			"latency_ms":      latency.Milliseconds(),
			"path":            c.Path(),
			"query_params":    c.Queries(),
			"route":           c.Route().Path,
			"content_type":    c.Get("Content-Type"),
			"content_length":  c.Get("Content-Length"),
			"error":           err != nil,
			"response_size":   len(c.Response().Body()),
			"response_status": c.Response().StatusCode(),
			"success":         status >= 200 && status < 400,
		}

		// Add sanitized request body if available
		body := getSanitizedBody(c)
		if body != nil {
			metadata["request_body"] = body
		}

		// Create detailed audit log
		metadataJSON, _ := json.Marshal(metadata)
		log := AuditLog{
			ID:         uuid.NewString(),
			UserID:     userID,
			ActorID:    userID,
			Action:     action,
			Resource:   resource,
			ResourceID: resourceID,
			IP:         ip,
			UserAgent:  userAgent,
			CreatedAt:  time.Now().UTC(),
			Details:    string(metadataJSON),
			Metadata:   metadata,
		}

		// Determine which logger to use - either provided or global
		logger := customLogger
		if logger == nil {
			var err error
			logger, err = GetGlobalAuditLogger()
			if err != nil {
				// If global logger isn't available, just log the error and continue
				applogger.LogError("AuditLoggerMiddleware: global audit logger not available",
					applogger.String("request_id", requestID),
					applogger.String("user_id", userID),
					applogger.String("path", c.Path()),
					applogger.ErrorField(err),
				)
				return err
			}
		}

		// Attempt to store the audit log but don't block the response
		// This helps prevent audit logging failures from affecting the user experience
		go func(ctx context.Context, auditLog AuditLog) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, logErr := logger.CreateAuditLog(ctx, auditLog)
			if logErr != nil {
				// Log the error but don't fail the request
				applogger.LogError("AuditLoggerMiddleware failed",
					applogger.String("request_id", requestID),
					applogger.String("user_id", userID),
					applogger.String("path", c.Path()),
					applogger.ErrorField(logErr),
				)
			}
		}(context.Background(), log)

		return err
	}
}
