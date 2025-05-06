package api

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)



// NewBaseHandler creates a new base handler
func NewBaseHandler(log *logger.Logger) *BaseHandler {
	if log == nil {
		log = logger.NewNoop()
	}

	return &BaseHandler{
		logger: log,
	}
}

// extractTenantID extracts the tenant ID from the request
func extractTenantID(c *fiber.Ctx) (string, error) {
	// Get tenant ID from header
	tenantID := c.Get(TenantIDHeader)
	if tenantID == "" {
		// Try to get from query
		tenantID = c.Query("tenant_id")
	}

	// Validate tenant ID
	if tenantID == "" {
		return "", newErrorResponse(c, fiber.StatusBadRequest, "Tenant ID is required")
	}

	return tenantID, nil
}

// newErrorResponse creates a new error response
func newErrorResponse(c *fiber.Ctx, status int, message string) error {
	if message == "" {
		message = DefaultErrorMessage
	}

	errorName := httpStatusToErrorName(status)

	response := ErrorResponse{
		Error:   errorName,
		Message: message,
		Status:  status,
	}

	return c.Status(status).JSON(response)
}

// httpStatusToErrorName converts an HTTP status code to an error name
func httpStatusToErrorName(status int) string {
	switch status {
	case fiber.StatusBadRequest:
		return "BadRequest"
	case fiber.StatusUnauthorized:
		return "Unauthorized"
	case fiber.StatusForbidden:
		return "Forbidden"
	case fiber.StatusNotFound:
		return "NotFound"
	case fiber.StatusConflict:
		return "Conflict"
	case fiber.StatusRequestTimeout:
		return "RequestTimeout"
	case fiber.StatusTooManyRequests:
		return "TooManyRequests"
	case fiber.StatusInternalServerError:
		return "InternalServerError"
	case fiber.StatusServiceUnavailable:
		return "ServiceUnavailable"
	default:
		return fmt.Sprintf("Error%d", status)
	}
}
