package account

import "context"

// BillingAccountService provides dynamic, type-agnostic account operations for user, project, and organization billing accounts.
type BillingAccountService interface {
	Create(ctx context.Context, accountType BillingAccountType, input interface{}) (interface{}, error)
	Get(ctx context.Context, accountType BillingAccountType, id string) (interface{}, error)
	Update(ctx context.Context, accountType BillingAccountType, input interface{}) (interface{}, error)
	List(ctx context.Context, accountType BillingAccountType, ownerID string, page, pageSize int) ([]interface{}, error)
	PerformAction(ctx context.Context, accountType BillingAccountType, accountID, action string, params map[string]interface{}) (map[string]interface{}, error)
	Delete(ctx context.Context, accountType BillingAccountType, id string) error
}
