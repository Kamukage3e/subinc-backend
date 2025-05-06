package architecture

import (
	"context"

)



// ListAWSResources fetches AWS resources for a tenant using AWSInventory
func ListAWSResources(ctx context.Context, tenantID string, inv *AWSInventory) ([]ResourceNode, error) {
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
