package commonutil

import (
	"github.com/google/uuid"
)

// GenerateUUID returns a new RFC4122 UUID string
// Centralized implementation to be used across all modules
func GenerateUUID() string {
	return uuid.NewString()
}

// IsValidUUID checks if a string is a valid UUID
func IsValidUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}
