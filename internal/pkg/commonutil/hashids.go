package commonutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// SecureDelimiter used to separate ID parts
	SecureDelimiter = "."
	// DefaultHashExpiry for temporary hashes (24 hours)
	DefaultHashExpiry = 24 * time.Hour
)

// IDHasher provides secure ID hashing and validation capabilities
// to prevent enumeration attacks and information leakage in REST APIs
type IDHasher struct {
	// Secret key used for HMAC
	secret []byte
	// Salt to add entropy
	salt []byte
	// Optional prefix for hashed IDs
	prefix string
}

// NewIDHasher creates a new instance of IDHasher
func NewIDHasher(secret, salt string, prefix string) *IDHasher {
	return &IDHasher{
		secret: []byte(secret),
		salt:   []byte(salt),
		prefix: prefix,
	}
}

// HashID securely hashes an ID to prevent sequential enumeration
// and exposure of internal database IDs in REST API responses
func (h *IDHasher) HashID(id string) string {
	if id == "" {
		return ""
	}

	// Create HMAC of the ID
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(id))
	mac.Write(h.salt)
	digest := mac.Sum(nil)

	// Encode the hash (use URL-safe base64)
	encoded := base64.RawURLEncoding.EncodeToString(digest)

	// Format as PREFIX.ORIGINAL_ID.HASH
	// Important: For systems where retrievability is needed, we keep the original ID
	// For maximum security, remove the original ID in production
	result := fmt.Sprintf("%s%s%s", id, SecureDelimiter, encoded[:16])

	if h.prefix != "" {
		result = h.prefix + SecureDelimiter + result
	}

	return result
}

// HashUUID creates an obfuscated representation of a UUID
// Useful for preventing UUID enumeration and hiding sequential UUIDs
func (h *IDHasher) HashUUID(id uuid.UUID) string {
	return h.HashID(id.String())
}

// VerifyHashedID validates that a hash corresponds to a given ID
// Returns true if the hash is valid for the given ID
func (h *IDHasher) VerifyHashedID(hashedID, originalID string) bool {
	if hashedID == "" || originalID == "" {
		return false
	}

	// Split by delimiter
	parts := strings.Split(hashedID, SecureDelimiter)

	// Handle prefixed IDs
	if h.prefix != "" {
		if len(parts) < 3 {
			return false
		}

		// Check prefix
		if parts[0] != h.prefix {
			return false
		}

		// Reconstruct to get actual ID and hash
		hashedID = strings.Join(parts[1:], SecureDelimiter)
		parts = parts[1:]
	}

	if len(parts) < 2 {
		return false
	}

	// The first part should be the original ID
	if parts[0] != originalID {
		return false
	}

	// Re-create the hash to verify
	expectedHash := h.HashID(originalID)
	return hashedID == expectedHash
}

// ExtractID extracts the original ID from a hashed ID
// Returns empty string if the hashed ID format is invalid
func (h *IDHasher) ExtractID(hashedID string) string {
	if hashedID == "" {
		return ""
	}

	// Split by delimiter
	parts := strings.Split(hashedID, SecureDelimiter)

	// Handle prefixed IDs
	if h.prefix != "" {
		if len(parts) < 3 {
			return ""
		}

		// Check prefix
		if parts[0] != h.prefix {
			return ""
		}

		return parts[1]
	}

	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

// CreateTemporaryHash creates a time-limited hash for temporary references
// expiryDuration is how long the hash should be valid
func (h *IDHasher) CreateTemporaryHash(id string, expiryDuration time.Duration) string {
	if id == "" {
		return ""
	}

	// Default expiry if not specified
	if expiryDuration <= 0 {
		expiryDuration = DefaultHashExpiry
	}

	// Calculate expiry timestamp
	expiry := time.Now().Add(expiryDuration).Unix()

	// Create a time-bound token: ID.EXPIRY.HASH
	payload := fmt.Sprintf("%s%s%d", id, SecureDelimiter, expiry)

	// Create HMAC of the payload
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	mac.Write(h.salt)
	digest := mac.Sum(nil)

	// Encode the hash
	encoded := base64.RawURLEncoding.EncodeToString(digest)

	// Format the final token
	result := fmt.Sprintf("%s%s%s", payload, SecureDelimiter, encoded[:16])

	if h.prefix != "" {
		result = h.prefix + SecureDelimiter + result
	}

	return result
}

// VerifyTemporaryHash validates a temporary hash and checks if it has expired
// Returns the ID and true if valid, empty string and false otherwise
func (h *IDHasher) VerifyTemporaryHash(hash string) (string, bool) {
	if hash == "" {
		return "", false
	}

	// Split by delimiter
	parts := strings.Split(hash, SecureDelimiter)

	// Handle prefixed hashes
	startIdx := 0
	if h.prefix != "" {
		if len(parts) < 4 {
			return "", false
		}

		if parts[0] != h.prefix {
			return "", false
		}

		startIdx = 1
	}

	// Need at least ID.EXPIRY.HASH
	if len(parts) < startIdx+3 {
		return "", false
	}

	id := parts[startIdx]
	expiry := parts[startIdx+1]

	// Verify expiry
	var expiryTime int64
	_, err := fmt.Sscanf(expiry, "%d", &expiryTime)
	if err != nil {
		return "", false
	}

	// Check if expired
	if time.Now().Unix() > expiryTime {
		return "", false
	}

	// Reconstruct the payload
	payload := fmt.Sprintf("%s%s%s", id, SecureDelimiter, expiry)

	// Create HMAC of the payload
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(payload))
	mac.Write(h.salt)
	digest := mac.Sum(nil)

	// Encode the hash
	expectedHash := base64.RawURLEncoding.EncodeToString(digest)[:16]
	providedHash := parts[len(parts)-1]

	// Verify the hash
	if expectedHash != providedHash {
		return "", false
	}

	return id, true
}
