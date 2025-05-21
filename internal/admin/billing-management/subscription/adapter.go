package subscription

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

type SubscriptionServiceAdapter struct {
	Store         *PostgresStore
	PluginManager *plugin.Manager
}

func NewSubscriptionServiceAdapter(store *PostgresStore, pluginManager *plugin.Manager) *SubscriptionServiceAdapter {
	return &SubscriptionServiceAdapter{Store: store, PluginManager: pluginManager}
}

func (a *SubscriptionServiceAdapter) CreateSubscription(input Subscription) (Subscription, error) {
	return a.Store.CreateSubscription(context.Background(), input)
}
func (a *SubscriptionServiceAdapter) UpdateSubscription(input Subscription) (Subscription, error) {
	return a.Store.UpdateSubscription(context.Background(), input)
}
func (a *SubscriptionServiceAdapter) PatchSubscription(id, action string) error {
	return a.Store.PatchSubscription(context.Background(), id, action)
}
func (a *SubscriptionServiceAdapter) DeleteSubscription(id string) error {
	return a.Store.DeleteSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) GetSubscription(id string) (Subscription, error) {
	return a.Store.GetSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) ListSubscriptions(accountID, status string, page, pageSize int) ([]Subscription, error) {
	return a.Store.ListSubscriptions(context.Background(), accountID, status, page, pageSize)
}
func (a *SubscriptionServiceAdapter) ChangePlanSubscription(id, planID string) error {
	return a.Store.ChangePlanSubscription(context.Background(), id, planID)
}
func (a *SubscriptionServiceAdapter) CancelSubscriptionNow(id string) error {
	return a.Store.CancelSubscriptionNow(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) ResumeSubscription(id string) error {
	return a.Store.ResumeSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) UpgradeNowSubscription(id string) error {
	return a.Store.UpgradeNowSubscription(context.Background(), id, "")
}

func (a *SubscriptionServiceAdapter) ProcessAutoRenewals() error {
	return a.Store.ProcessAutoRenewals(context.Background())
}

// Plugin management methods - implement the interface
func (a *SubscriptionServiceAdapter) ListSubscriptionPlugins(ctx context.Context) ([]string, error) {
	return a.PluginManager.ListPlugins("subscription"), nil
}

func (a *SubscriptionServiceAdapter) GetSubscriptionPlugin(ctx context.Context, pluginName string) (SubscriptionPlugin, error) {
	if pluginName == "" {
		logger.LogError("GetSubscriptionPlugin: plugin name required")
		return nil, fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("subscription", pluginName)
	if !ok {
		logger.LogError("GetSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("subscription plugin not found")
	}
	plugin, ok := p.(SubscriptionPlugin)
	if !ok {
		logger.LogError("GetSubscriptionPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("invalid plugin type")
	}
	return plugin, nil
}

func (a *SubscriptionServiceAdapter) RegisterSubscriptionPlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("RegisterSubscriptionPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("subscription", pluginName)
	if !ok {
		logger.LogError("RegisterSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("subscription plugin not found")
	}
	_, ok = p.(SubscriptionPlugin)
	if !ok {
		logger.LogError("RegisterSubscriptionPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	// No Initialize method for SubscriptionPlugin, so just return success
	return nil
}

func (a *SubscriptionServiceAdapter) UnregisterSubscriptionPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("UnregisterSubscriptionPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("subscription", pluginName); err != nil {
		logger.LogError("UnregisterSubscriptionPlugin: failed", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}

func (a *SubscriptionServiceAdapter) ConfigureSubscriptionPlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("ConfigureSubscriptionPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("subscription", pluginName)
	if !ok {
		logger.LogError("ConfigureSubscriptionPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("subscription plugin not found")
	}
	_, ok = p.(SubscriptionPlugin)
	if !ok {
		logger.LogError("ConfigureSubscriptionPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	// No Initialize method for SubscriptionPlugin, so just return success
	return nil
}

func (a *SubscriptionServiceAdapter) DisableSubscriptionPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("DisableSubscriptionPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("subscription", pluginName); err != nil {
		logger.LogError("DisableSubscriptionPlugin: failed to unregister plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}

// Add methods as needed, e.g.:
// func (a *SubscriptionServiceAdapter) CreateSubscription(s Subscription) (Subscription, error) {
// 	return a.Store.CreateSubscription(context.Background(), s)
// }
// ...

type PlanServiceAdapter struct {
	Store *PostgresStore
}

func (a *PlanServiceAdapter) CreatePlan(input Plan) (Plan, error) {
	return a.Store.CreatePlan(context.Background(), input)
}
func (a *PlanServiceAdapter) UpdatePlan(input Plan) (Plan, error) {
	return a.Store.UpdatePlan(context.Background(), input)
}
func (a *PlanServiceAdapter) GetPlan(id string) (Plan, error) {
	return a.Store.GetPlan(context.Background(), id)
}
func (a *PlanServiceAdapter) ListPlans(activeOnly bool, page, pageSize int) ([]Plan, error) {
	return a.Store.ListPlans(context.Background(), activeOnly, page, pageSize)
}
func (a *PlanServiceAdapter) DeletePlan(id string) error {
	return a.Store.DeletePlan(context.Background(), id)
}

type UsageServiceAdapter struct {
	Store *PostgresStore
}

func (a *UsageServiceAdapter) CreateUsage(input Usage) (Usage, error) {
	return a.Store.CreateUsage(context.Background(), input)
}
func (a *UsageServiceAdapter) ListUsage(accountID, metric, period string, page, pageSize int) ([]Usage, error) {
	return a.Store.ListUsage(context.Background(), accountID, metric, period, page, pageSize)
}
