package account

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

// BillingAccountServiceAdapter provides dynamic, type-agnostic account operations.
type BillingAccountServiceAdapter struct {
	Store         *PostgresStore
	PluginManager *plugin.Manager
}

func NewBillingAccountServiceAdapter(store *PostgresStore, pluginManager *plugin.Manager) *BillingAccountServiceAdapter {
	return &BillingAccountServiceAdapter{Store: store, PluginManager: pluginManager}
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
	case []*ProjectBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []UserBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []*UserBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []OrganizationBillingAccount:
		for i := range v {
			list = append(list, v[i])
		}
	case []*OrganizationBillingAccount:
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

func (a *BillingAccountServiceAdapter) GetAccountPlugin(ctx context.Context, pluginName string) (interface{}, error) {
	if pluginName == "" {
		logger.LogError("GetAccountPlugin: plugin name required")
		return nil, fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("account", pluginName)
	if !ok {
		logger.LogError("GetAccountPlugin: plugin not found", logger.String("plugin", pluginName))
		return nil, fmt.Errorf("plugin not found")
	}
	return p, nil
}

func (a *BillingAccountServiceAdapter) ListAccountPlugins() []string {
	return a.PluginManager.ListPlugins("account")
}

func (a *BillingAccountServiceAdapter) RegisterAccountPlugin(ctx context.Context, plugin interface{}) error {
	if plugin == nil {
		logger.LogError("RegisterAccountPlugin: plugin instance required")
		return fmt.Errorf("plugin instance required")
	}
	err := a.PluginManager.RegisterPlugin("account", plugin)
	if err != nil {
		logger.LogError("RegisterAccountPlugin: failed to register plugin", logger.ErrorField(err))
		return fmt.Errorf("failed to register plugin")
	}
	return nil
}

func (a *BillingAccountServiceAdapter) UnregisterAccountPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("UnregisterAccountPlugin: plugin name required")
		return fmt.Errorf("plugin name required")
	}
	err := a.PluginManager.UnregisterPlugin("account", pluginName)
	if err != nil {
		logger.LogError("UnregisterAccountPlugin: failed to unregister plugin", logger.String("plugin", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}
