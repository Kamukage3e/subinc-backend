package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Common error codes
const (
	CodeValidationError      = "VALIDATION_ERROR"
	CodeNotFoundError        = "NOT_FOUND"
	CodeUnauthorizedError    = "UNAUTHORIZED"
	CodeForbiddenError       = "FORBIDDEN"
	CodeConflictError        = "CONFLICT"
	CodeInternalError        = "INTERNAL_ERROR"
	CodeServiceUnavailable   = "SERVICE_UNAVAILABLE"
	CodeUnprocessableEntity  = "UNPROCESSABLE_ENTITY"
	CodeNotImplementedError  = "NOT_IMPLEMENTED"
	CodeBadRequestError      = "BAD_REQUEST"
	CodeTooManyRequestsError = "TOO_MANY_REQUESTS"
	CodeGatewayTimeoutError  = "GATEWAY_TIMEOUT"
)

// APIError represents an API error with consistent format
type APIError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Field      string `json:"field,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
	HTTPStatus int    `json:"-"`
	Err        error  `json:"-"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error
func (e *APIError) Unwrap() error {
	return e.Err
}

// MarshalJSON marshals the error to JSON
func (e *APIError) MarshalJSON() ([]byte, error) {
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    e.Code,
			"message": e.Message,
		},
	}

	if e.Field != "" {
		response["error"].(map[string]interface{})["field"] = e.Field
	}

	if e.TraceID != "" {
		response["error"].(map[string]interface{})["trace_id"] = e.TraceID
	}

	return json.Marshal(response)
}

// NewValidationError creates a validation error for a specific field
func NewValidationError(field, message string) *APIError {
	return &APIError{
		Code:       CodeValidationError,
		Message:    message,
		Field:      field,
		HTTPStatus: http.StatusBadRequest,
	}
}

// NewNotFoundError creates a not found error for a resource
func NewNotFoundError(resource string) *APIError {
	return &APIError{
		Code:       CodeNotFoundError,
		Message:    fmt.Sprintf("%s not found", resource),
		HTTPStatus: http.StatusNotFound,
	}
}

// NewUnauthorizedError creates an unauthorized error
func NewUnauthorizedError(message string) *APIError {
	if message == "" {
		message = "authentication required"
	}
	return &APIError{
		Code:       CodeUnauthorizedError,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
	}
}

// NewForbiddenError creates a forbidden error
func NewForbiddenError(message string) *APIError {
	if message == "" {
		message = "permission denied"
	}
	return &APIError{
		Code:       CodeForbiddenError,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewConflictError creates a conflict error
func NewConflictError(resource string, message string) *APIError {
	if message == "" {
		message = fmt.Sprintf("%s already exists", resource)
	}
	return &APIError{
		Code:       CodeConflictError,
		Message:    message,
		HTTPStatus: http.StatusConflict,
	}
}

// NewInternalError creates an internal server error
func NewInternalError(err error) *APIError {
	return &APIError{
		Code:       CodeInternalError,
		Message:    "an internal server error occurred",
		HTTPStatus: http.StatusInternalServerError,
		Err:        err,
	}
}

// NewBadRequestError creates a bad request error
func NewBadRequestError(message string) *APIError {
	if message == "" {
		message = "invalid request"
	}
	return &APIError{
		Code:       CodeBadRequestError,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
	}
}

// NewServiceUnavailableError creates a service unavailable error
func NewServiceUnavailableError(message string) *APIError {
	if message == "" {
		message = "service temporarily unavailable"
	}
	return &APIError{
		Code:       CodeServiceUnavailable,
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

// NewNotImplementedError creates a not implemented error
func NewNotImplementedError(feature string) *APIError {
	return &APIError{
		Code:       CodeNotImplementedError,
		Message:    fmt.Sprintf("%s is not implemented yet", feature),
		HTTPStatus: http.StatusNotImplemented,
	}
}

// NewTooManyRequestsError creates a too many requests error
func NewTooManyRequestsError() *APIError {
	return &APIError{
		Code:       CodeTooManyRequestsError,
		Message:    "too many requests, please try again later",
		HTTPStatus: http.StatusTooManyRequests,
	}
}

// WithTraceID adds a trace ID to the error
func (e *APIError) WithTraceID(traceID string) *APIError {
	e.TraceID = traceID
	return e
}

// WithError wraps an error
func (e *APIError) WithError(err error) *APIError {
	e.Err = err
	return e
}

// HandleAPIError handles API errors consistently in Fiber handlers
func HandleAPIError(c *fiber.Ctx, err error, log *logger.Logger) error {
	// Extract the API error
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		// Create a generic internal error if not an APIError
		apiErr = NewInternalError(err)
	}

	// Add trace ID from request context if available
	traceID := c.Get("X-Trace-ID")
	if traceID != "" {
		apiErr.TraceID = traceID
	}

	// Log the error appropriately
	if apiErr.HTTPStatus >= http.StatusInternalServerError {
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

// IsAPIError checks if an error is an APIError
func IsAPIError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr)
}

// Is checks if an error is of a specific API error code
func Is(err error, code string) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == code
	}
	return false
}
