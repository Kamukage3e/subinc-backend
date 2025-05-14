package tax

import (
	"context"
)

type TaxInfoService interface {
	SetTaxInfo(ctx context.Context, info TaxInfo) (TaxInfo, error)
	GetTaxInfo(ctx context.Context, tenantID string) (TaxInfo, error)
	ListTaxPlugins(ctx context.Context) ([]TaxPlugin, error)
	SetTaxPluginConfig(ctx context.Context, config TaxPluginConfig) (TaxPluginConfig, error)
	GetTaxPluginConfig(ctx context.Context, tenantID string) (TaxPluginConfig, error)
}

type TaxPluginService interface {
	CalculateTax(ctx context.Context, invoice Invoice, account Account, tenantID string) (taxAmount, taxRate float64, err error)
}
