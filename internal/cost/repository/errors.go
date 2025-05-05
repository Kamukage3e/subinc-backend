package repository

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/subinc/subinc-backend/internal/cost/domain"
)

// Standard repository error types
var (
	// ErrNotFound is returned when a resource is not found
	ErrNotFound = errors.New("resource not found")

	// ErrDuplicate is returned when a unique constraint is violated
	ErrDuplicate = errors.New("duplicate resource")

	// ErrInvalidInput is returned when the input to a repository method is invalid
	ErrInvalidInput = errors.New("invalid input")

	// ErrDatabase is returned when a database operation fails
	ErrDatabase = errors.New("database error")

	// ErrCacheOperation is returned when a cache operation fails
	ErrCacheOperation = errors.New("cache operation failed")

	// ErrBatchOperation is returned when a batch operation fails
	ErrBatchOperation = errors.New("batch operation failed")

	// ErrTenantIsolation is returned when a tenant isolation boundary is violated
	ErrTenantIsolation = errors.New("tenant isolation violation")

	// ErrTxBegin is returned when a transaction cannot be started
	ErrTxBegin = errors.New("cannot begin transaction")

	// ErrTxCommit is returned when a transaction commit fails
	ErrTxCommit = errors.New("cannot commit transaction")

	// ErrTxRollback is returned when a transaction rollback fails
	ErrTxRollback = errors.New("cannot rollback transaction")

	// ErrOperationTimeout is returned when a database operation times out
	ErrOperationTimeout = errors.New("operation timeout")

	// ErrConnectionFailed is returned when a database connection fails
	ErrConnectionFailed = errors.New("connection failed")

	// ErrMaxRetries is returned when an operation has been retried the maximum number of times
	ErrMaxRetries = errors.New("max retries exceeded")
)

// PostgresErrorCode defines common PostgreSQL error codes we want to handle explicitly
type PostgresErrorCode string

// Common PostgreSQL error codes
const (
	// UniqueViolation is the PostgreSQL error code for unique constraint violations
	UniqueViolation PostgresErrorCode = "23505"

	// ForeignKeyViolation is the PostgreSQL error code for foreign key constraint violations
	ForeignKeyViolation PostgresErrorCode = "23503"

	// NotNullViolation is the PostgreSQL error code for not null constraint violations
	NotNullViolation PostgresErrorCode = "23502"

	// CheckViolation is the PostgreSQL error code for check constraint violations
	CheckViolation PostgresErrorCode = "23514"

	// ConnectionFailure is the PostgreSQL error code for connection failures
	ConnectionFailure PostgresErrorCode = "08006"

	// ConnectionDoesNotExist is the PostgreSQL error code for when a connection doesn't exist
	ConnectionDoesNotExist PostgresErrorCode = "08003"

	// TooManyConnections is the PostgreSQL error code for too many connections
	TooManyConnections PostgresErrorCode = "53300"

	// QueryCanceled is the PostgreSQL error code for when a query is canceled (e.g., due to timeout)
	QueryCanceled PostgresErrorCode = "57014"

	// DiskFull is the PostgreSQL error code for when the disk is full
	DiskFull PostgresErrorCode = "53100"

	// OutOfMemory is the PostgreSQL error code for out of memory
	OutOfMemory PostgresErrorCode = "53200"
)

// RepositoryError represents a structured error from the repository layer
type RepositoryError struct {
	// Err is the underlying error
	Err error

	// Operation is the operation that was being performed
	Operation string

	// Resource is the type of resource being operated on
	Resource string

	// Code is an optional error code (e.g., from PostgreSQL)
	Code string

	// RetryAfter is a hint about when to retry the operation, if applicable
	RetryAfter int
}

// Error implements the error interface
func (e RepositoryError) Error() string {
	var b strings.Builder
	b.WriteString(e.Operation)
	b.WriteString(" operation on ")
	b.WriteString(e.Resource)
	b.WriteString(" failed")

	if e.Code != "" {
		b.WriteString(" (code: ")
		b.WriteString(e.Code)
		b.WriteString(")")
	}

	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}

	if e.RetryAfter > 0 {
		b.WriteString(fmt.Sprintf(" - retry after %d seconds", e.RetryAfter))
	}

	return b.String()
}

// Unwrap returns the underlying error
func (e RepositoryError) Unwrap() error {
	return e.Err
}

// Is checks if the target error matches this RepositoryError
func (e RepositoryError) Is(target error) bool {
	if target == nil {
		return false
	}

	// Check if the target is the same as this error
	if err, ok := target.(RepositoryError); ok {
		return e.Err == err.Err && e.Code == err.Code
	}

	// Check if the target is the same as the underlying error
	return errors.Is(e.Err, target)
}

// NewRepositoryError creates a new RepositoryError
func NewRepositoryError(operation, resource string, err error) RepositoryError {
	return RepositoryError{
		Err:       err,
		Operation: operation,
		Resource:  resource,
	}
}

// NewDuplicateError creates a RepositoryError for duplicate entries
func NewDuplicateError(resource, identifier string) RepositoryError {
	return RepositoryError{
		Err:       ErrDuplicate,
		Operation: "create",
		Resource:  resource,
		Code:      string(UniqueViolation),
	}
}

// NewNotFoundError creates a RepositoryError for not found resources
func NewNotFoundError(resource, identifier string) RepositoryError {
	return RepositoryError{
		Err:       ErrNotFound,
		Operation: "find",
		Resource:  resource,
	}
}

// mapPostgresError maps PostgreSQL errors to domain errors
func mapPostgresError(err error, resource string) error {
	if err == nil {
		return nil
	}

	// Check for no rows error
	if errors.Is(err, pgx.ErrNoRows) {
		switch resource {
		case "cost":
			return domain.ErrCostDataNotFound
		case "budget":
			return domain.ErrBudgetNotFound
		case "anomaly":
			return domain.ErrAnomalyNotFound
		case "forecast":
			return domain.ErrForecastNotFound
		case "cost_import":
			return domain.NewEntityNotFoundError("cost_import", "")
		default:
			return NewNotFoundError(resource, "")
		}
	}

	// Check for PostgreSQL-specific errors
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		repoErr := RepositoryError{
			Err:      err,
			Resource: resource,
			Code:     pgErr.Code,
		}

		switch PostgresErrorCode(pgErr.Code) {
		case UniqueViolation:
			repoErr.Operation = "create or update"
			repoErr.Err = ErrDuplicate
			return repoErr
		case ForeignKeyViolation:
			repoErr.Operation = "create or update"
			repoErr.Err = fmt.Errorf("related resource not found: %s", pgErr.Detail)
			return repoErr
		case NotNullViolation, CheckViolation:
			repoErr.Operation = "create or update"
			repoErr.Err = ErrInvalidInput
			return repoErr
		case ConnectionFailure, ConnectionDoesNotExist:
			repoErr.Operation = "connect"
			repoErr.Err = ErrConnectionFailed
			repoErr.RetryAfter = 5 // Suggest retry after 5 seconds
			return repoErr
		case TooManyConnections:
			repoErr.Operation = "connect"
			repoErr.Err = ErrConnectionFailed
			repoErr.RetryAfter = 10 // Suggest retry after 10 seconds
			return repoErr
		case QueryCanceled:
			repoErr.Operation = "query"
			repoErr.Err = ErrOperationTimeout
			return repoErr
		case DiskFull, OutOfMemory:
			repoErr.Operation = "internal"
			repoErr.Err = fmt.Errorf("database resource exhausted: %s", pgErr.Message)
			return repoErr
		}
	}

	// Generic database error
	return NewRepositoryError("database", resource, err)
}

// isNilOrEmpty checks if a string is nil or empty
func isNilOrEmpty(s string) bool {
	return s == ""
}

// validateCost validates a cost object before database operations
func validateCost(cost *domain.Cost) error {
	if cost == nil {
		return domain.ErrInvalidResource
	}
	return cost.Validate()
}

// validateCostImport validates a cost import object before database operations
func validateCostImport(costImport *domain.CostImport) error {
	if costImport == nil {
		return domain.ErrInvalidResource
	}

	if isNilOrEmpty(costImport.TenantID) {
		return domain.ErrInvalidTenant
	}

	if isNilOrEmpty(costImport.ID) {
		return domain.NewValidationError("id", "must not be empty")
	}

	return nil
}

// validateBudget validates a budget object before database operations
func validateBudget(budget *domain.Budget) error {
	if budget == nil {
		return domain.ErrInvalidResource
	}

	if isNilOrEmpty(budget.TenantID) {
		return domain.ErrInvalidTenant
	}

	if isNilOrEmpty(budget.ID) {
		return domain.NewValidationError("id", "must not be empty")
	}

	if isNilOrEmpty(budget.Name) {
		return domain.NewValidationError("name", "must not be empty")
	}

	if budget.Amount <= 0 {
		return domain.NewValidationError("amount", "must be greater than zero")
	}

	return nil
}

// validateAnomaly validates an anomaly object before database operations
func validateAnomaly(anomaly *domain.Anomaly) error {
	if anomaly == nil {
		return domain.ErrInvalidResource
	}

	if isNilOrEmpty(anomaly.TenantID) {
		return domain.ErrInvalidTenant
	}

	if isNilOrEmpty(anomaly.ID) {
		return domain.NewValidationError("id", "must not be empty")
	}

	return nil
}

// validateForecast validates a forecast object before database operations
func validateForecast(forecast *domain.Forecast) error {
	if forecast == nil {
		return domain.ErrInvalidResource
	}

	if isNilOrEmpty(forecast.TenantID) {
		return domain.ErrInvalidTenant
	}

	if isNilOrEmpty(forecast.ID) {
		return domain.NewValidationError("id", "must not be empty")
	}

	return nil
}

// isResourceOwner checks if the tenant owns the specified resource
// Real implementation must query the database for ownership validation.
// This function is not used in production code and is removed for SaaS readiness.
