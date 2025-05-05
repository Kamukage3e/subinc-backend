package provisioning

import (
	"context"
	"time"
)

// ProvisionRequest represents a request to provision a cloud resource.
type ProvisionRequest struct {
	TenantID    string            `json:"tenant_id"`
	OrgID       string            `json:"org_id"`
	ProjectID   string            `json:"project_id"`
	Provider    string            `json:"provider"` // aws, azure, gcp
	Resource    string            `json:"resource"` // e.g., ec2, s3, vm, storage
	Config      map[string]string `json:"config"`   // resource-specific config
	RequestedBy string            `json:"requested_by"`
}

// ProvisionStatus represents the status of a provisioning operation.
type ProvisionStatus struct {
	ID           string           `json:"id"`
	Request      ProvisionRequest `json:"request"`
	Status       string           `json:"status"` // pending, running, success, failed
	Message      string           `json:"message"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	TerraformHCL string           `json:"terraform_hcl"` // HCL for client export
}

// Provisioner defines the interface for resource provisioning and lifecycle management.
type Provisioner interface {
	Provision(ctx context.Context, req *ProvisionRequest) (*ProvisionStatus, error)
	GetStatus(ctx context.Context, id string) (*ProvisionStatus, error)
	List(ctx context.Context, tenantID, orgID, projectID string) ([]*ProvisionStatus, error)
	Cancel(ctx context.Context, id string) error
}
