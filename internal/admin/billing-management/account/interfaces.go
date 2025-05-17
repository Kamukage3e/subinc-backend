package account

import "context"

type AccountService interface {
	CreateAccount(input Account) (Account, error)
	UpdateAccount(input Account) (Account, error)
	GetAccount(id string) (Account, error)
	ListAccounts(tenantID string, page, pageSize int) ([]Account, error)
	PerformAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (interface{}, error)
	DeleteAccount(id string) error
}

// AccountPlugin defines a hot-pluggable interface for account logic
// Each implementation can be dynamically loaded and configured at runtime
// All methods must be concurrency-safe and production-grade
// Extend as needed for SaaS account extensibility
type AccountPlugin interface {
	Name() string    // Unique name for the account plugin
	Version() string // Version in semver format

	// Core account operations (extend as needed)
	OnCreate(ctx context.Context, account *Account) error
	OnUpdate(ctx context.Context, account *Account) error
	OnDelete(ctx context.Context, accountID string) error
	Capabilities() []string
	Initialize(config map[string]interface{}) error // Initialize with configuration
}