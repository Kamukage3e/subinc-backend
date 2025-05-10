package billing_management

import "fmt"

// ErrNotFound is returned when a resource is not found
var ErrNotFound = &Error{Code: "NOT_FOUND", Message: "resource not found"}

// ErrValidation is returned for validation errors
var ErrValidation = &Error{Code: "VALIDATION_ERROR", Message: "validation failed"}

// ErrConflict is returned for conflict errors (e.g., duplicate)
var ErrConflict = &Error{Code: "CONFLICT", Message: "resource conflict"}

// ErrInternal is returned for internal server errors
var ErrInternal = &Error{Code: "INTERNAL_ERROR", Message: "internal server error"}

// Error is a custom error type for API errors
// Implements error interface
// Code is a stable string for programmatic use
// Message is user-friendly
// Field is optional for validation errors
// Wraps an underlying error if present
type Error struct {
	Code    string
	Message string
	Field   string
	Err     error
}

func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// NewValidationError returns a validation error for a specific field
func NewValidationError(field, msg string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

// NewNotFoundError returns a not found error for a resource
func NewNotFoundError(resource string) *Error {
	return &Error{
		Code:    "NOT_FOUND",
		Message: fmt.Sprintf("%s not found", resource),
	}
}

// NewConflictError returns a conflict error for a resource
func NewConflictError(resource string) *Error {
	return &Error{
		Code:    "CONFLICT",
		Message: fmt.Sprintf("%s conflict", resource),
	}
}

// NewInternalError returns an internal error, wrapping the original error
func NewInternalError(err error) *Error {
	return &Error{
		Code:    "INTERNAL_ERROR",
		Message: "internal server error",
		Err:     err,
	}
}

// IsValidationError returns true if err is a validation error
func IsValidationError(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == "VALIDATION_ERROR"
}

// IsNotFoundError returns true if err is a not found error
func IsNotFoundError(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == "NOT_FOUND"
}

// IsConflictError returns true if err is a conflict error
func IsConflictError(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == "CONFLICT"
}

// IsInternalError returns true if err is an internal error
func IsInternalError(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Code == "INTERNAL_ERROR"
}
