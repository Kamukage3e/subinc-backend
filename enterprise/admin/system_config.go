package admin

import (
	"context"
	"time"
)

// SystemConfig represents a system-wide configuration key/value.
type SystemConfig struct {
	Key       string    `json:"key" db:"key"`
	Value     string    `json:"value" db:"value"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// SystemConfigStore defines storage for system configuration.
type SystemConfigStore interface {
	Get(ctx context.Context, key string) (*SystemConfig, error)
	Set(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]*SystemConfig, error)
}
