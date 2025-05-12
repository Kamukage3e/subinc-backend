package commonutil

import (
	"fmt"
)

// DBError represents a database operation error with operation name
type DBError struct {
	Op  string
	Err error
}

// Error implements the error interface
func (e *DBError) Error() string {
	return fmt.Sprintf("db error: %s: %s", e.Op, e.Err.Error())
}

// Unwrap returns the underlying error
func (e *DBError) Unwrap() error {
	return e.Err
}

// WrapDBErr wraps a database error with an operation name
func WrapDBErr(op string, err error) error {
	return &DBError{Op: op, Err: err}
}

// APIError represents an API error with code, message and field info
type APIError struct {
	Code    string
	Message string
	Field   string
	Err     error
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *APIError) Unwrap() error {
	return e.Err
}

// NewValidationError returns a validation error for a specific field
func NewValidationError(field, msg string) *APIError {
	return &APIError{
		Code:    "VALIDATION_ERROR",
		Message: msg,
		Field:   field,
	}
}

// NewNotFoundError returns a not found error for a resource
func NewNotFoundError(resource string) *APIError {
	return &APIError{
		Code:    "NOT_FOUND",
		Message: fmt.Sprintf("%s not found", resource),
	}
}

// NewConflictError returns a conflict error for a resource
func NewConflictError(resource string) *APIError {
	return &APIError{
		Code:    "CONFLICT",
		Message: fmt.Sprintf("%s conflict", resource),
	}
}

// NewInternalError returns an internal error, wrapping the original error
func NewInternalError(err error) *APIError {
	return &APIError{
		Code:    "INTERNAL_ERROR",
		Message: "internal server error",
		Err:     err,
	}
}

// IsValidationError returns true if err is a validation error
func IsValidationError(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Code == "VALIDATION_ERROR"
}

// IsNotFoundError returns true if err is a not found error
func IsNotFoundError(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Code == "NOT_FOUND"
}

// IsConflictError returns true if err is a conflict error
func IsConflictError(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Code == "CONFLICT"
}

// IsInternalError returns true if err is an internal error
func IsInternalError(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Code == "INTERNAL_ERROR"
}
