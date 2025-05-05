package cloud

import (
	"context"
	"fmt"

	"github.com/subinc/subinc-backend/internal/cost/cloud/aws"
	"github.com/subinc/subinc-backend/internal/cost/cloud/azure"
	"github.com/subinc/subinc-backend/internal/cost/cloud/gcp"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// DefaultProviderFactory implements the ProviderFactory interface
type DefaultProviderFactory struct {
	logger *logger.Logger
}

// NewProviderFactory creates a new provider factory
func NewProviderFactory(log *logger.Logger) ProviderFactory {
	if log == nil {
		// Use the NewNoop function that we found in the logger package
		log = logger.NewNoop()
	}
	return &DefaultProviderFactory{
		logger: log,
	}
}

// CreateProvider creates a cloud provider instance based on credentials
func (f *DefaultProviderFactory) CreateProvider(ctx context.Context, provider domain.CloudProvider, credentials map[string]string) (CostDataProvider, error) {
	switch provider {
	case domain.AWS:
		// Use AWS implementation
		f.logger.Debug("Creating AWS cost provider")
		return aws.NewAWSCostProvider(ctx, credentials, f.logger)
	case domain.Azure:
		// Import Azure implementation
		f.logger.Debug("Creating Azure cost provider")
		return azure.NewAzureCostProvider(ctx, credentials, f.logger)
	case domain.GCP:
		// Import GCP implementation
		f.logger.Debug("Creating GCP cost provider")
		return gcp.NewGCPCostProvider(ctx, credentials, f.logger)
	default:
		err := fmt.Errorf("unsupported cloud provider: %s", provider)
		f.logger.Error("Failed to create provider", logger.ErrorField(err))
		return nil, err
	}
}
