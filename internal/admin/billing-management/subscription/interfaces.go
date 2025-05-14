package subscription



type PlanService interface {
	CreatePlan(input Plan) (Plan, error)
	UpdatePlan(input Plan) (Plan, error)
	GetPlan(id string) (Plan, error)
	ListPlans(activeOnly bool, page, pageSize int) ([]Plan, error)
	DeletePlan(id string) error
}

type UsageService interface {
	CreateUsage(input Usage) (Usage, error)
	ListUsage(accountID, metric, period string, page, pageSize int) ([]Usage, error)
}


type SubscriptionService interface {
	CreateSubscription(input Subscription) (Subscription, error)
	UpdateSubscription(input Subscription) (Subscription, error)
	PatchSubscription(id, action string) error
	DeleteSubscription(id string) error
	GetSubscription(id string) (Subscription, error)
	ListSubscriptions(accountID, status string, page, pageSize int) ([]Subscription, error)
	ChangePlanSubscription(id, planID string) error
	CancelSubscriptionNow(id string) error
	ResumeSubscription(id string) error
	UpgradeNowSubscription(id string) error
}