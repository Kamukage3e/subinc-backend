package domain

import (
	"errors"
	"fmt"
)

// Common domain errors
var (
	// General errors
	ErrInvalidProvider    = errors.New("invalid cloud provider")
	ErrInvalidTimeRange   = errors.New("invalid time range")
	ErrInvalidGranularity = errors.New("invalid granularity")
	ErrInvalidTenant      = errors.New("invalid tenant")
	ErrInvalidResource    = errors.New("invalid resource")

	// Cost data errors
	ErrCostDataNotFound = errors.New("cost data not found")
	ErrCostImportFailed = errors.New("cost import failed")

	// Budget errors
	ErrBudgetNotFound = errors.New("budget not found")
	ErrBudgetInvalid  = errors.New("budget is invalid")

	// Anomaly errors
	ErrAnomalyNotFound = errors.New("anomaly not found")
	ErrAnomalyInvalid  = errors.New("anomaly is invalid")

	// Forecast errors
	ErrForecastNotFound = errors.New("forecast not found")
	ErrForecastInvalid  = errors.New("forecast is invalid")

	// Security errors
	ErrUnauthorized   = errors.New("unauthorized access")
	ErrTenantMismatch = errors.New("tenant ID mismatch")

	// Billing errors
	ErrInvalidPlan     = errors.New("invalid billing plan")
	ErrInvalidUsage    = errors.New("invalid usage event")
	ErrInvalidInvoice  = errors.New("invalid invoice")
	ErrInvalidPayment  = errors.New("invalid payment")
	ErrInvalidAuditLog = errors.New("invalid audit log")
)

// EntityNotFoundError is a structured error for when an entity is not found
type EntityNotFoundError struct {
	Entity string
	ID     string
}

func (e EntityNotFoundError) Error() string {
	return fmt.Sprintf("%s with ID '%s' not found", e.Entity, e.ID)
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// MultiValidationError represents multiple validation errors
type MultiValidationError struct {
	Errors []ValidationError
}

func (e MultiValidationError) Error() string {
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}
	return fmt.Sprintf("%d validation errors occurred", len(e.Errors))
}

// NewEntityNotFoundError creates a new EntityNotFoundError
func NewEntityNotFoundError(entity, id string) error {
	return EntityNotFoundError{
		Entity: entity,
		ID:     id,
	}
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, message string) error {
	return ValidationError{
		Field:   field,
		Message: message,
	}
}

// IsEntityNotFoundError checks if an error is an EntityNotFoundError
func IsEntityNotFoundError(err error) bool {
	_, ok := err.(EntityNotFoundError)
	return ok
}

// IsValidationError checks if an error is a ValidationError
func IsValidationError(err error) bool {
	_, ok := err.(ValidationError)
	return ok || errors.Is(err, ErrInvalidResource)
}

// NewDiscountNotFoundError creates a new EntityNotFoundError for discounts
func NewDiscountNotFoundError(id string) error {
	return EntityNotFoundError{
		Entity: "discount",
		ID:     id,
	}
}

// IsDiscountNotFoundError checks if an error is an EntityNotFoundError for discounts
func IsDiscountNotFoundError(err error) bool {
	if e, ok := err.(EntityNotFoundError); ok {
		return e.Entity == "discount"
	}
	return false
}

// NewCouponNotFoundError creates a new EntityNotFoundError for coupons
func NewCouponNotFoundError(id string) error {
	return EntityNotFoundError{
		Entity: "coupon",
		ID:     id,
	}
}

// IsCouponNotFoundError checks if an error is an EntityNotFoundError for coupons
func IsCouponNotFoundError(err error) bool {
	if e, ok := err.(EntityNotFoundError); ok {
		return e.Entity == "coupon"
	}
	return false
}
