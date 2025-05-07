package provisioningtypes

import (
	"time"
)

type ProvisionRequest struct {
	TenantID    string            `json:"tenant_id"`
	OrgID       string            `json:"org_id"`
	ProjectID   string            `json:"project_id"`
	Provider    string            `json:"provider"` // aws, azure, gcp
	Resource    string            `json:"resource"` // e.g., ec2, s3, vm, storage
	Config      map[string]string `json:"config"`   // resource-specific config
	RequestedBy string            `json:"requested_by"`
}

type ProvisionStatus struct {
	ID           string           `json:"id"`
	Request      ProvisionRequest `json:"request"`
	Status       string           `json:"status"` // pending, running, success, failed
	Message      string           `json:"message"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	TerraformHCL string           `json:"terraform_hcl"` // HCL for client export
}
