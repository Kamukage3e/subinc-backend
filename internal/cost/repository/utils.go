package repository

import (
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// itoa converts an integer to a string - helper for SQL parameter placeholders
func itoa(i int) string {
	return strconv.Itoa(i)
}

// min returns the minimum of two durations
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// RetryOptions configures the retry behavior
type RetryOptions struct {
	// MaxRetries is the maximum number of retries to attempt
	MaxRetries int

	// InitialBackoff is the initial delay before retrying
	InitialBackoff time.Duration

	// MaxBackoff is the maximum delay between retries
	MaxBackoff time.Duration

	// BackoffFactor is the multiplier for successive backoff delays
	BackoffFactor float64

	// JitterFactor adds randomness to the backoff to prevent thundering herd
	JitterFactor float64
}

// DefaultRetryOptions returns sensible defaults for retry options
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		BackoffFactor:  2.0,
		JitterFactor:   0.2,
	}
}

// TxOptions represents transaction options
type TxOptions struct {
	// Isolation is the transaction isolation level
	Isolation pgx.TxIsoLevel

	// ReadOnly indicates if the transaction is read only
	ReadOnly bool

	// DeferrableMode indicates if the transaction is deferrable
	DeferrableMode pgx.TxDeferrableMode
}

// DefaultTxOptions returns default transaction options
func DefaultTxOptions() TxOptions {
	return TxOptions{
		Isolation:      pgx.ReadCommitted,
		ReadOnly:       false,
		DeferrableMode: pgx.NotDeferrable,
	}
}
