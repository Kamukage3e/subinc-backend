package account

import (
	"context"
	"fmt"
)

// BillingAccountServiceAdapter provides dynamic, type-agnostic account operations.
type BillingAccountServiceAdapter struct {
	Store *PostgresStore
}

// Create creates an account of any type.
func (a *BillingAccountServiceAdapter) Create(ctx context.Context, accountType BillingAccountType, acct interface{}) (interface{}, error) {
	return a.Store.CreateBillingAccount(ctx, accountType, acct)
}

// Get fetches an account of any type by ID.
func (a *BillingAccountServiceAdapter) Get(ctx context.Context, accountType BillingAccountType, id string) (interface{}, error) {
	return a.Store.GetBillingAccount(ctx, accountType, id)
}

// Update updates an account of any type.
func (a *BillingAccountServiceAdapter) Update(ctx context.Context, accountType BillingAccountType, acct interface{}) (interface{}, error) {
	return a.Store.UpdateBillingAccount(ctx, accountType, acct)
}

// List lists accounts of any type, returns []interface{} of the correct struct.
func (a *BillingAccountServiceAdapter) List(ctx context.Context, accountType BillingAccountType, ownerID string, page, pageSize int) ([]interface{}, error) {
	res, err := a.Store.ListBillingAccounts(ctx, accountType, ownerID, page, pageSize)
	if err != nil {
		return nil, err
	}
	var list []interface{}
	switch v := res.(type) {
	case []ProjectBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []UserBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []OrganizationBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	default:
		return nil, fmt.Errorf("unexpected type in List: %T", res)
	}
	return list, nil
}

// PerformAction performs an action on any account type.
func (a *BillingAccountServiceAdapter) PerformAction(ctx context.Context, accountType BillingAccountType, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	return a.Store.PerformBillingAccountAction(ctx, accountType, accountID, action, params)
}

// Delete deletes an account of any type by ID.
func (a *BillingAccountServiceAdapter) Delete(ctx context.Context, accountType BillingAccountType, id string) error {
	return a.Store.DeleteBillingAccount(ctx, accountType, id)
}
