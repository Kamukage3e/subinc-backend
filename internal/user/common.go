package user

import (
	"strconv"

	"github.com/google/uuid"
	"github.com/speps/go-hashids/v2"
	"github.com/spf13/viper"
)

// hashID is initialized once per process. Salt must be set via config for SaaS security.
var hashID *hashids.HashID

func init() {
	salt := getSalt()
	if salt == "" {
		// Architectural decision: Do not allow insecure default salt in production.
		// If salt is missing, fail fast and log a clear error.
		panic("HASHID_SALT must be set in configuration for secure operation")
	}
	hd := hashids.NewData()
	hd.Salt = salt
	hd.MinLength = 12
	var err error
	hashID, err = hashids.NewWithData(hd)
	if err != nil {
		panic("failed to initialize hashids: " + err.Error())
	}
}

func getSalt() string {
	return viper.GetString("HASHID_SALT")
}

// HasRole returns true if the user has the specified role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AddRole adds a role to the user if not already present.
func (u *User) AddRole(role string) {
	if !u.HasRole(role) {
		u.Roles = append(u.Roles, role)
	}
}

// RemoveRole removes a role from the user.
func (u *User) RemoveRole(role string) {
	roles := make([]string, 0, len(u.Roles))
	for _, r := range u.Roles {
		if r != role {
			roles = append(roles, r)
		}
	}
	u.Roles = roles
}

// GetAttribute returns the value for a user attribute, if present.
func (u *User) GetAttribute(key string) (string, bool) {
	val, ok := u.Attributes[key]
	return val, ok
}

// SetAttribute sets a user attribute key/value.
func (u *User) SetAttribute(key, value string) {
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	u.Attributes[key] = value
}

// RemoveAttribute deletes a user attribute by key.
func (u *User) RemoveAttribute(key string) {
	if u.Attributes != nil {
		delete(u.Attributes, key)
	}
}

// GenerateUUID returns a new random UUID string for use as a user ID.
func GenerateUUID() string {
	return uuid.NewString()
}

// HashID returns a hashid-encoded string for the user's numeric ID.
// Returns error if ID is not numeric or encoding fails.
func (u *User) HashID() (string, error) {
	idInt, err := strconv.ParseInt(u.ID, 10, 64)
	if err != nil {
		return "", err
	}
	hid, err := hashID.EncodeInt64([]int64{idInt})
	if err != nil {
		return "", err
	}
	return hid, nil
}
