package fee

import (
	"context"
)

// FeeService provides a service layer for fee-related operations
type FeeService interface {
	CreateFee(ctx context.Context, f Fee) (Fee, error)
	GetFee(ctx context.Context, id string) (Fee, error)
	UpdateFee(ctx context.Context, f Fee) (Fee, error)
	DeleteFee(ctx context.Context, id string) error
	ListFees(ctx context.Context, page, pageSize int) ([]Fee, error)

	// Plugin management methods
	SetFeePluginConfig(ctx context.Context, tenantID, pluginName string) (FeePluginConfig, error)
	GetFeePluginConfig(ctx context.Context, tenantID string) (FeePluginConfig, error)
	DisableFeePlugin(ctx context.Context, tenantID, pluginName string) error

	// Additional plugin methods to match handlers
	ListFeePlugins(ctx context.Context) ([]string, error)
	GetFeePlugin(ctx context.Context, pluginName string) (FeePlugin, error)
	RegisterFeePlugin(ctx context.Context, pluginName string, config map[string]interface{}) error
	UnregisterFeePlugin(ctx context.Context, pluginName string) error
}
