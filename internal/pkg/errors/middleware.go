package errors

import (
	"crypto/rand"
	"encoding/hex"


	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// ErrorHandlerMiddleware creates a middleware to handle errors consistently
func ErrorHandlerMiddleware(log *logger.Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		// Extract the API error
		var apiErr *APIError
		if !IsAPIError(err) {
			// Handle Fiber's errors
			if fiberErr, ok := err.(*fiber.Error); ok {
				// Create appropriate API error from Fiber error
				switch fiberErr.Code {
				case fiber.StatusNotFound:
					apiErr = NewNotFoundError("route")
				case fiber.StatusMethodNotAllowed:
					apiErr = NewBadRequestError("method not allowed")
				case fiber.StatusUnprocessableEntity:
					apiErr = &APIError{
						Code:       CodeUnprocessableEntity,
						Message:    fiberErr.Message,
						HTTPStatus: fiberErr.Code,
					}
				case fiber.StatusInternalServerError:
					apiErr = NewInternalError(fiberErr)
				case fiber.StatusBadRequest:
					apiErr = NewBadRequestError(fiberErr.Message)
				default:
					apiErr = &APIError{
						Code:       "ERROR",
						Message:    fiberErr.Message,
						HTTPStatus: fiberErr.Code,
					}
				}
			} else {
				// Create a generic internal error for other error types
				apiErr = NewInternalError(err)
			}
		} else {
			// Use the APIError directly
			apiErr = err.(*APIError)
		}

		// Add trace ID from request context if available
		traceID := c.Get("X-Trace-ID")
		if traceID != "" {
			apiErr.TraceID = traceID
		}

		// Log the error appropriately
		if apiErr.HTTPStatus >= fiber.StatusInternalServerError {
			// Log server errors with stack trace and original error
			log.Error("api_error",
				logger.String("code", apiErr.Code),
				logger.String("message", apiErr.Message),
				logger.String("trace_id", apiErr.TraceID),
				logger.ErrorField(apiErr.Err))
		} else {
			// Log client errors at info level
			log.Info("api_error",
				logger.String("code", apiErr.Code),
				logger.String("message", apiErr.Message),
				logger.String("trace_id", apiErr.TraceID))
		}

		// Return JSON response with appropriate status code
		return c.Status(apiErr.HTTPStatus).JSON(apiErr)
	}
}

// RegisterErrorHandler registers the error handling middleware with a Fiber app
func RegisterErrorHandler(app *fiber.App, log *logger.Logger) {
	// Add middleware to generate and set trace ID
	app.Use(func(c *fiber.Ctx) error {
		// Generate and set trace ID
		traceID := c.Get("X-Trace-ID")
		if traceID == "" {
			traceID = generateTraceID()
			c.Set("X-Trace-ID", traceID)
		}
		return c.Next()
	})

	// Set the global error handler
	// Note: Must be done at app creation time using fiber.Config{ErrorHandler: ...}
	// This function is provided for documentation, but the actual handler should be passed
	// during app creation like:
	// app := fiber.New(fiber.Config{
	//     ErrorHandler: errors.ErrorHandlerMiddleware(logger),
	// })
}

// Generate a random trace ID
func generateTraceID() string {
	// Generate 16 random bytes
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to a simple string if random generation fails
		return "trace-fallback-" + hex.EncodeToString([]byte{1, 2, 3, 4})
	}

	return hex.EncodeToString(bytes)
}


