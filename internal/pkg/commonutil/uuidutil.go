package commonutil

import (
	"github.com/google/uuid"
)

// GenerateUUID returns a new RFC4122 UUID string
// Centralized implementation to be used across all modules
func GenerateUUID() string {
	return uuid.NewString()
}
