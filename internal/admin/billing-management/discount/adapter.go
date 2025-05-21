package discount

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

// DiscountServiceAdapter provides dynamic, type-agnostic account operations.
type DiscountServiceAdapter struct {
	Store         *PostgresStore
	PluginManager *plugin.Manager
}

func NewDiscountServiceAdapter(store *PostgresStore, pluginManager *plugin.Manager) *DiscountServiceAdapter {
	return &DiscountServiceAdapter{Store: store, PluginManager: pluginManager}
}

func (a *DiscountServiceAdapter) CreateDiscount(d Discount) (Discount, error) {
	return a.Store.CreateDiscount(context.Background(), d)
}
func (a *DiscountServiceAdapter) UpdateDiscount(d Discount) (Discount, error) {
	return a.Store.UpdateDiscount(context.Background(), d)
}
func (a *DiscountServiceAdapter) DeleteDiscount(id string) error {
	return a.Store.DeleteDiscount(context.Background(), id)
}
func (a *DiscountServiceAdapter) GetDiscount(id string) (Discount, error) {
	return a.Store.GetDiscount(context.Background(), id)
}
func (a *DiscountServiceAdapter) GetDiscountByCode(code string) (Discount, error) {
	return a.Store.GetDiscountByCode(context.Background(), code)
}
func (a *DiscountServiceAdapter) ListDiscounts(activeOnly bool, page, pageSize int) ([]Discount, error) {
	return a.Store.ListDiscounts(context.Background(), activeOnly, page, pageSize)
}

// Plugin-related methods
func (a *DiscountServiceAdapter) ListDiscountPlugins(ctx context.Context) ([]string, error) { 
	return a.PluginManager.ListPlugins("discount"), nil
}

func (a *DiscountServiceAdapter) GetDiscountPlugin(ctx context.Context, pluginName string) (DiscountPlugin, error) {
	if pluginName == "" {
		logger.LogError("GetDiscountPlugin: plugin name required")
		return nil, fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("discount", pluginName)
	if !ok {
		logger.LogError("GetDiscountPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("discount plugin not found")
	}
	plugin, ok := p.(DiscountPlugin)
	if !ok {
		logger.LogError("GetDiscountPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return nil, fmt.Errorf("invalid plugin type")
	}
	return plugin, nil
}

func (a *DiscountServiceAdapter) RegisterDiscountPlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("RegisterDiscountPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("discount", pluginName)
	if !ok {
		logger.LogError("RegisterDiscountPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("discount plugin not found")
	}
	plugin, ok := p.(DiscountPlugin)
	if !ok {
		logger.LogError("RegisterDiscountPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("RegisterDiscountPlugin: failed to initialize plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to initialize plugin")
	}
	return nil
}

func (a *DiscountServiceAdapter) UnregisterDiscountPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("UnregisterDiscountPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("discount", pluginName); err != nil {
		logger.LogError("UnregisterDiscountPlugin: failed", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}

func (a *DiscountServiceAdapter) ConfigureDiscountPlugin(ctx context.Context, pluginName string, config map[string]interface{}) error {
	if pluginName == "" {
		logger.LogError("ConfigureDiscountPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	p, ok := a.PluginManager.GetPlugin("discount", pluginName)
	if !ok {
		logger.LogError("ConfigureDiscountPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return fmt.Errorf("discount plugin not found")
	}
	plugin, ok := p.(DiscountPlugin)
	if !ok {
		logger.LogError("ConfigureDiscountPlugin: invalid plugin type", logger.String("plugin_name", pluginName))
		return fmt.Errorf("invalid plugin type")
	}
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("ConfigureDiscountPlugin: failed to initialize plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to initialize plugin")
	}
	return nil
}

func (a *DiscountServiceAdapter) DisableDiscountPlugin(ctx context.Context, pluginName string) error {
	if pluginName == "" {
		logger.LogError("DisableDiscountPlugin: plugin name required")
		return fmt.Errorf("plugin name is required")
	}
	if err := a.PluginManager.UnregisterPlugin("discount", pluginName); err != nil {
		logger.LogError("DisableDiscountPlugin: failed to unregister plugin", logger.String("plugin_name", pluginName), logger.ErrorField(err))
		return fmt.Errorf("failed to unregister plugin")
	}
	return nil
}

type CreditServiceAdapter struct {
	Store *PostgresStore
}

func (a *CreditServiceAdapter) CreateCredit(c Credit) (Credit, error) {
	return a.Store.CreateCredit(context.Background(), c)
}
func (a *CreditServiceAdapter) UpdateCredit(c Credit) (Credit, error) {
	return a.Store.UpdateCredit(context.Background(), c)
}
func (a *CreditServiceAdapter) PatchCredit(id, action string, amount float64) error {
	return a.Store.PatchCredit(context.Background(), id, action, amount)
}
func (a *CreditServiceAdapter) DeleteCredit(id string) error {
	return a.Store.DeleteCredit(context.Background(), id)
}
func (a *CreditServiceAdapter) GetCredit(id string) (Credit, error) {
	return a.Store.GetCredit(context.Background(), id)
}
func (a *CreditServiceAdapter) ListCredits(accountID, invoiceID, status string, page, pageSize int) ([]Credit, error) {
	return a.Store.ListCredits(context.Background(), accountID, invoiceID, status, page, pageSize)
}
func (a *CreditServiceAdapter) ApplyCreditsToInvoice(invoiceID string) error {
	return a.Store.ApplyCreditsToInvoice(context.Background(), invoiceID)
}
func (a *CreditServiceAdapter) GetExchangeRate(ctx context.Context, base, quote string) (ExchangeRate, error) {
	return a.Store.GetExchangeRate(ctx, base, quote)
}

type CouponServiceAdapter struct {
	Store *PostgresStore
}

func (a *CouponServiceAdapter) CreateCoupon(input Coupon) (Coupon, error) {
	return a.Store.CreateCoupon(context.Background(), input)
}
func (a *CouponServiceAdapter) UpdateCoupon(input Coupon) (Coupon, error) {
	return a.Store.UpdateCoupon(context.Background(), input)
}
func (a *CouponServiceAdapter) DeleteCoupon(id string) error {
	return a.Store.DeleteCoupon(context.Background(), id)
}
func (a *CouponServiceAdapter) GetCoupon(id string) (Coupon, error) {
	return a.Store.GetCoupon(context.Background(), id)
}
func (a *CouponServiceAdapter) GetCouponByCode(code string) (Coupon, error) {
	return a.Store.GetCouponByCode(context.Background(), code)
}
func (a *CouponServiceAdapter) ListCoupons(discountID string, isActive *bool, page, pageSize int) ([]Coupon, error) {
	return a.Store.ListCoupons(context.Background(), discountID, isActive, page, pageSize)
}
func (a *CouponServiceAdapter) RedeemCoupon(code, accountID string) (Coupon, error) {
	return a.Store.RedeemCoupon(context.Background(), code, accountID)
}
