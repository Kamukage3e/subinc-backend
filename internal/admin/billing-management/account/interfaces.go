package account

import "context"

type ProjectBillingAccountService interface {
	CreateProjectBillingAccount(ctx context.Context, input ProjectBillingAccount) (ProjectBillingAccount, error)
	UpdateProjectBillingAccount(ctx context.Context, input ProjectBillingAccount) (ProjectBillingAccount, error)
	GetProjectBillingAccount(ctx context.Context, id string) (ProjectBillingAccount, error)
	ListProjectBillingAccounts(ctx context.Context, projectID string, page, pageSize int) ([]ProjectBillingAccount, error)
	PerformProjectBillingAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error)
	DeleteProjectBillingAccount(ctx context.Context, id string) error
}

type OrgBillingAccountService interface {
	CreateOrgBillingAccount(ctx context.Context, input OrgBillingAccount) (OrgBillingAccount, error)
	UpdateOrgBillingAccount(ctx context.Context, input OrgBillingAccount) (OrgBillingAccount, error)
	GetOrgBillingAccount(ctx context.Context, id string) (OrgBillingAccount, error)
	ListOrgBillingAccounts(ctx context.Context, orgID string, page, pageSize int) ([]OrgBillingAccount, error)
	PerformOrgBillingAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error)
	DeleteOrgBillingAccount(ctx context.Context, id string) error
}
