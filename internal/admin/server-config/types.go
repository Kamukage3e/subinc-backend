package server_config

import (
	"time"
)

// ServerConfig represents a runtime, DB-backed, hot-reloadable server-side configuration entry.
// All config is versioned, auditable, and modifiable at runtime via admin API.
type ServerConfig struct {
	Key       string    `json:"key" db:"key"`
	Value     string    `json:"value" db:"value"`
	Version   int       `json:"version" db:"version"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// ServerConfigHistory tracks changes for audit/versioning.
type ServerConfigHistory struct {
	ID        int       `json:"id" db:"id"`
	Key       string    `json:"key" db:"key"`
	Value     string    `json:"value" db:"value"`
	Version   int       `json:"version" db:"version"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	UpdatedBy string    `json:"updated_by" db:"updated_by"`
}
