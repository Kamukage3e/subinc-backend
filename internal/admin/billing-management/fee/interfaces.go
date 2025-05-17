package fee

import (
	"context"
)

type FeeService interface {
	CreateFee(ctx context.Context, f Fee) (Fee, error)
	GetFee(ctx context.Context, id string) (Fee, error)
	UpdateFee(ctx context.Context, f Fee) (Fee, error)
	DeleteFee(ctx context.Context, id string) error
	SetFeePluginConfig(ctx context.Context, tenantID, pluginName string) (FeePluginConfig, error)
	GetFeePluginConfig(ctx context.Context, tenantID string) (FeePluginConfig, error)
}
