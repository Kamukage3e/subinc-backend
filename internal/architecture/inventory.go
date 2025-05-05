package architecture

import (
	"context"

	"github.com/subinc/subinc-backend/internal/architecture/types"
)

// AWSResourceInventory abstracts AWS resource inventory for testability and no import cycle
// Real prod interface, no placeholders

type AWSResourceInventory interface {
	GetCredentials(ctx context.Context, tenantID string) (map[string]string, error)
	GetAccountID(ctx context.Context, tenantID string) (string, error)
	ListResources(ctx context.Context, accountID string, credentials map[string]string) ([]types.ResourceNode, error)
}

// ListAWSResources fetches AWS resources for a tenant using AWSInventory
func ListAWSResources(ctx context.Context, tenantID string, inv *AWSInventory) ([]types.ResourceNode, error) {
	credentials, err := inv.GetCredentials(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	accountID, err := inv.GetAccountID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return inv.ListResources(ctx, accountID, credentials)
}
