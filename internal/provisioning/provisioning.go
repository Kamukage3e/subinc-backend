package provisioning

import (
	"context"

	provisioningtypes "github.com/subinc/subinc-backend/internal/provisioningtypes"
)

// Provisioner defines the interface for resource provisioning and lifecycle management.
type Provisioner interface {
	Provision(ctx context.Context, req *provisioningtypes.ProvisionRequest) (*provisioningtypes.ProvisionStatus, error)
	GetStatus(ctx context.Context, id string) (*provisioningtypes.ProvisionStatus, error)
	List(ctx context.Context, tenantID, orgID, projectID string) ([]*provisioningtypes.ProvisionStatus, error)
	Cancel(ctx context.Context, id string) error
}
