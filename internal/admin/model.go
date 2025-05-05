package admin

import "time"

// AdminUser represents a privileged admin user (superuser, org admin, etc.)
type AdminUser struct {
	ID           string    `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Roles        []string  `json:"roles" db:"roles"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// AdminRole represents an admin role (e.g., superuser, compliance, billing)
type AdminRole struct {
	ID          string   `json:"id" db:"id"`
	Name        string   `json:"name" db:"name"`
	Permissions []string `json:"permissions" db:"permissions"`
}

// AdminPermission represents a named admin permission
type AdminPermission struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
}

// Tenant represents a real SaaS tenant/org. All fields are required for prod.
type Tenant struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Settings  string    `json:"settings" db:"settings"` // JSON blob for org settings/policies
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
