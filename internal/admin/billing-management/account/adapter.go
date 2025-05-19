package account

import "context"

type ProjectBillingAccountServiceAdapter struct {
	Store *PostgresStore
}

func (a *ProjectBillingAccountServiceAdapter) CreateProjectBillingAccount(ctx context.Context, acct ProjectBillingAccount) (ProjectBillingAccount, error) {
	return a.Store.CreateProjectBillingAccount(ctx, acct)
}
func (a *ProjectBillingAccountServiceAdapter) GetProjectBillingAccount(ctx context.Context, id string) (ProjectBillingAccount, error) {
	return a.Store.GetProjectBillingAccount(ctx, id)
}
func (a *ProjectBillingAccountServiceAdapter) UpdateProjectBillingAccount(ctx context.Context, acct ProjectBillingAccount) (ProjectBillingAccount, error) {
	return a.Store.UpdateProjectBillingAccount(ctx, acct)
}
func (a *ProjectBillingAccountServiceAdapter) ListProjectBillingAccounts(ctx context.Context, projectID string, page, pageSize int) ([]ProjectBillingAccount, error) {
	return a.Store.ListProjectBillingAccounts(ctx, projectID, page, pageSize)
}
func (a *ProjectBillingAccountServiceAdapter) PerformProjectBillingAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	return a.Store.PerformProjectBillingAccountAction(ctx, accountID, action, params)
}
func (a *ProjectBillingAccountServiceAdapter) DeleteProjectBillingAccount(ctx context.Context, id string) error {
	return a.Store.DeleteProjectBillingAccount(ctx, id)
}
