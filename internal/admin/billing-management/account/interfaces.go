package account

import "context"





type AccountService interface {
	CreateAccount(input Account) (Account, error)
	UpdateAccount(input Account) (Account, error)
	GetAccount(id string) (Account, error)
	ListAccounts(tenantID string, page, pageSize int) ([]Account, error)
	PerformAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (interface{}, error)
}