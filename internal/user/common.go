package user

import "github.com/google/uuid"

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
