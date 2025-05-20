package subscription

import "context"

type SubscriptionServiceAdapter struct {
	Store *PostgresStore
}

func (a *SubscriptionServiceAdapter) CreateSubscription(input Subscription) (Subscription, error) {
	return a.Store.CreateSubscription(context.Background(), input)
}
func (a *SubscriptionServiceAdapter) UpdateSubscription(input Subscription) (Subscription, error) {
	return a.Store.UpdateSubscription(context.Background(), input)
}
func (a *SubscriptionServiceAdapter) PatchSubscription(id, action string) error {
	return a.Store.PatchSubscription(context.Background(), id, action)
}
func (a *SubscriptionServiceAdapter) DeleteSubscription(id string) error {
	return a.Store.DeleteSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) GetSubscription(id string) (Subscription, error) {
	return a.Store.GetSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) ListSubscriptions(accountID, status string, page, pageSize int) ([]Subscription, error) {
	return a.Store.ListSubscriptions(context.Background(), accountID, status, page, pageSize)
}
func (a *SubscriptionServiceAdapter) ChangePlanSubscription(id, planID string) error {
	return a.Store.ChangePlanSubscription(context.Background(), id, planID)
}
func (a *SubscriptionServiceAdapter) CancelSubscriptionNow(id string) error {
	return a.Store.CancelSubscriptionNow(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) ResumeSubscription(id string) error {
	return a.Store.ResumeSubscription(context.Background(), id)
}
func (a *SubscriptionServiceAdapter) UpgradeNowSubscription(id string) error {
	return a.Store.UpgradeNowSubscription(context.Background(), id, "")
}

func (a *SubscriptionServiceAdapter) ProcessAutoRenewals() error {
	return a.Store.ProcessAutoRenewals(context.Background())
}

// Add methods as needed, e.g.:
// func (a *SubscriptionServiceAdapter) CreateSubscription(s Subscription) (Subscription, error) {
// 	return a.Store.CreateSubscription(context.Background(), s)
// }
// ...

type PlanServiceAdapter struct {
	Store *PostgresStore
}

func (a *PlanServiceAdapter) CreatePlan(input Plan) (Plan, error) {
	return a.Store.CreatePlan(context.Background(), input)
}
func (a *PlanServiceAdapter) UpdatePlan(input Plan) (Plan, error) {
	return a.Store.UpdatePlan(context.Background(), input)
}
func (a *PlanServiceAdapter) GetPlan(id string) (Plan, error) {
	return a.Store.GetPlan(context.Background(), id)
}
func (a *PlanServiceAdapter) ListPlans(activeOnly bool, page, pageSize int) ([]Plan, error) {
	return a.Store.ListPlans(context.Background(), activeOnly, page, pageSize)
}
func (a *PlanServiceAdapter) DeletePlan(id string) error {
	return a.Store.DeletePlan(context.Background(), id)
}

type UsageServiceAdapter struct {
	Store *PostgresStore
}

func (a *UsageServiceAdapter) CreateUsage(input Usage) (Usage, error) {
	return a.Store.CreateUsage(context.Background(), input)
}
func (a *UsageServiceAdapter) ListUsage(accountID, metric, period string, page, pageSize int) ([]Usage, error) {
	return a.Store.ListUsage(context.Background(), accountID, metric, period, page, pageSize)
}
