package user

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// HashPassword hashes a password using Argon2id. Returns base64(salt|hash).
// All parameters are set for strong security in SaaS. Never returns plaintext or leaks info.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("failed to generate salt")
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b := append(salt, hash...)
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// VerifyPassword checks a password against a base64(salt|hash) Argon2id hash.
// Returns (true, nil) if valid, (false, nil) if not, or (false, error) if format is invalid.
func VerifyPassword(password, encoded string) (bool, error) {
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(b) < argonSaltLen+argonKeyLen {
		return false, errors.New("invalid password hash format")
	}
	salt := b[:argonSaltLen]
	hash := b[argonSaltLen:]
	cmp := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if len(hash) != len(cmp) {
		return false, nil
	}
	for i := range hash {
		if hash[i] != cmp[i] {
			return false, nil
		}
	}
	return true, nil
}
