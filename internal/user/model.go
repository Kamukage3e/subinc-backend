package user

import (
	"time"

	"os"

	"github.com/google/uuid"
	"github.com/speps/go-hashids/v2"
)

// User represents a real SaaS user. All fields are required for prod.
type User struct {
	ID           string            `json:"id" db:"id"`
	TenantID     string            `json:"tenant_id" db:"tenant_id"`
	Username     string            `json:"username" db:"username"`
	Email        string            `json:"email" db:"email"`
	PasswordHash string            `json:"-" db:"password_hash"`
	Roles        []string          `json:"roles" db:"roles"`
	Attributes   map[string]string `json:"attributes" db:"attributes"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at" db:"updated_at"`
}

var hashID *hashids.HashID

func init() {
	salt := os.Getenv("HASHID_SALT")
	if salt == "" {
		salt = "subinc-default-salt-change-me" // secure default, must override in prod
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

func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (u *User) AddRole(role string) {
	if !u.HasRole(role) {
		u.Roles = append(u.Roles, role)
	}
}

func (u *User) RemoveRole(role string) {
	roles := make([]string, 0, len(u.Roles))
	for _, r := range u.Roles {
		if r != role {
			roles = append(roles, r)
		}
	}
	u.Roles = roles
}

func (u *User) GetAttribute(key string) (string, bool) {
	val, ok := u.Attributes[key]
	return val, ok
}

func (u *User) SetAttribute(key, value string) {
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	u.Attributes[key] = value
}

func (u *User) RemoveAttribute(key string) {
	if u.Attributes != nil {
		delete(u.Attributes, key)
	}
}

// GenerateUUID returns a new random UUID string for use as a user ID.
func GenerateUUID() string {
	return uuid.NewString()
}
