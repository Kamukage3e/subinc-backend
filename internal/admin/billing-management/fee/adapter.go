package fee

import "context"

type FeeServiceAdapter struct {
	Store *PostgresStore
}

func (a *FeeServiceAdapter) CreateFee(ctx context.Context, f Fee) (Fee, error) {
	return a.Store.CreateFee(ctx, f)
}
func (a *FeeServiceAdapter) GetFee(ctx context.Context, id string) (Fee, error) {
	return a.Store.GetFee(ctx, id)
}
func (a *FeeServiceAdapter) UpdateFee(ctx context.Context, f Fee) (Fee, error) {
	return a.Store.UpdateFee(ctx, f)
}
func (a *FeeServiceAdapter) DeleteFee(ctx context.Context, id string) error {
	return a.Store.DeleteFee(ctx, id)
}
func (a *FeeServiceAdapter) SetFeePluginConfig(ctx context.Context, tenantID, pluginName string) (FeePluginConfig, error) {
	return a.Store.SetFeePluginConfig(ctx, tenantID, pluginName)
}
func (a *FeeServiceAdapter) GetFeePluginConfig(ctx context.Context, tenantID string) (FeePluginConfig, error) {
	return a.Store.GetFeePluginConfig(ctx, tenantID)
}
