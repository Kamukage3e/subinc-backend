package service

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/spf13/viper"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/enterprise/notifications"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type SubscriptionService interface {
	CreateSubscription(ctx context.Context, sub *domain.Subscription) error
	UpdateSubscription(ctx context.Context, sub *domain.Subscription) error
	CancelSubscription(ctx context.Context, id string) error
	SchedulePlanChange(ctx context.Context, id, planID string, changeAt time.Time) error
	ProcessDunning(ctx context.Context, id string) error
	ProcessProration(ctx context.Context, id, newPlanID string) error
	GetSubscriptionByID(ctx context.Context, id string) (*domain.Subscription, error)
	ListSubscriptions(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.Subscription, int, error)
	NextInvoicePreview(ctx context.Context, accountID string) (*domain.Invoice, error)
	ApplyScheduledPlanChanges(ctx context.Context) error
	ProcessDunningAndGrace(ctx context.Context) error
	UpgradeNow(ctx context.Context, id, planID string) error
}

type subscriptionService struct {
	repo          repository.BillingRepository
	logger        *logger.Logger
	notifications notifications.NotificationStore
}

func NewSubscriptionService(repo repository.BillingRepository, log *logger.Logger, notif notifications.NotificationStore) SubscriptionService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &subscriptionService{repo: repo, logger: log, notifications: notif}
}

func (s *subscriptionService) CreateSubscription(ctx context.Context, sub *domain.Subscription) error {
	if sub == nil {
		s.logger.Error("nil subscription provided")
		return domain.NewValidationError("subscription", "must not be nil")
	}
	sub.ID = uuid.NewString()
	sub.Status = "active"
	sub.CreatedAt = time.Now().UTC()
	sub.UpdatedAt = sub.CreatedAt
	return s.repo.CreateSubscription(ctx, sub)
}

func (s *subscriptionService) UpdateSubscription(ctx context.Context, sub *domain.Subscription) error {
	if sub == nil {
		s.logger.Error("nil subscription provided")
		return domain.NewValidationError("subscription", "must not be nil")
	}
	sub.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateSubscription(ctx, sub)
}

func (s *subscriptionService) CancelSubscription(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty subscription id for cancel")
		return domain.NewValidationError("subscription_id", "must not be empty")
	}
	sub, err := s.repo.GetSubscriptionByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get subscription for cancel", logger.ErrorField(err))
		return err
	}
	now := time.Now().UTC()
	sub.Status = "canceled"
	sub.CanceledAt = timePtr(now)
	sub.UpdatedAt = now
	return s.repo.UpdateSubscription(ctx, sub)
}

func (s *subscriptionService) SchedulePlanChange(ctx context.Context, id, planID string, changeAt time.Time) error {
	if id == "" || planID == "" || changeAt.IsZero() {
		s.logger.Error("invalid schedule plan change params")
		return domain.NewValidationError("subscription", "id, planID, and changeAt required")
	}
	sub, err := s.repo.GetSubscriptionByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get subscription for schedule plan change", logger.ErrorField(err))
		return err
	}
	oldPlanID := sub.PlanID
	sub.ScheduledPlanID = stringPtr(planID)
	sub.ScheduledChangeAt = timePtr(changeAt)
	sub.Status = "scheduled"
	sub.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
		return err
	}
	actorID := "system"
	if v := ctx.Value("actor_id"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			actorID = s
		}
	}
	details := map[string]interface{}{
		"old_plan_id":     oldPlanID,
		"new_plan_id":     planID,
		"subscription_id": id,
		"action":          "schedule_plan_change",
		"change_at":       changeAt,
	}
	detailsJSON, _ := json.Marshal(details)
	log := &domain.AuditLog{
		ID:        uuid.NewString(),
		ActorID:   actorID,
		Action:    "subscription_plan_change",
		TargetID:  id,
		Timestamp: time.Now().UTC(),
		Details:   string(detailsJSON),
	}
	_ = s.repo.CreateAuditLog(ctx, log)
	// Send notification to account email
	acct, err := s.repo.GetBillingAccountByID(ctx, sub.AccountID)
	if err == nil && acct.Email != "" && s.notifications != nil {
		n := &notifications.Notification{
			ID:        uuid.NewString(),
			Type:      "email",
			Recipient: acct.Email,
			Subject:   "Your subscription plan change is scheduled",
			Body:      "Your subscription will change from plan " + oldPlanID + " to " + planID + " on " + changeAt.Format(time.RFC1123) + ".",
			Status:    "pending",
			CreatedAt: time.Now().UTC(),
		}
		_ = s.notifications.Send(ctx, n)
	}
	return nil
}

func (s *subscriptionService) ProcessDunning(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty subscription id for dunning")
		return domain.NewValidationError("subscription_id", "must not be empty")
	}
	sub, err := s.repo.GetSubscriptionByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get subscription for dunning", logger.ErrorField(err))
		return err
	}
	sub.Status = "dunning"
	sub.DunningUntil = timePtr(time.Now().Add(72 * time.Hour))
	sub.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateSubscription(ctx, sub)
}

func (s *subscriptionService) ProcessProration(ctx context.Context, id, newPlanID string) error {
	if id == "" || newPlanID == "" {
		s.logger.Error("invalid proration params")
		return domain.NewValidationError("subscription", "id and newPlanID required")
	}
	sub, err := s.repo.GetSubscriptionByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get subscription for proration", logger.ErrorField(err))
		return err
	}
	if sub.Status != "active" {
		return domain.NewValidationError("subscription", "must be active for proration")
	}
	plan, err := s.repo.GetBillingPlanByID(ctx, sub.PlanID)
	if err != nil {
		s.logger.Error("failed to get current plan for proration", logger.ErrorField(err))
		return err
	}
	// Parse pricing JSON (expecting {"price": float64, "currency": string})
	var planPricing struct {
		Price    float64 `json:"price"`
		Currency string  `json:"currency"`
	}
	if err := json.Unmarshal([]byte(plan.Pricing), &planPricing); err != nil {
		s.logger.Error("failed to parse plan pricing JSON", logger.ErrorField(err))
		return domain.NewValidationError("plan_pricing", "invalid pricing JSON")
	}
	// Calculate unused value (simple daily proration)
	now := time.Now().UTC()
	daysLeft := int(sub.CurrentPeriodEnd.Sub(now).Hours() / 24)
	totalDays := int(sub.CurrentPeriodEnd.Sub(sub.CurrentPeriodStart).Hours() / 24)
	if daysLeft <= 0 || totalDays <= 0 {
		daysLeft = 0
		totalDays = 1
	}
	oldDaily := planPricing.Price / float64(totalDays)
	unusedValue := oldDaily * float64(daysLeft)
	if unusedValue > 0.01 {
		credit := &domain.Credit{
			ID:        uuid.NewString(),
			AccountID: sub.AccountID,
			Amount:    unusedValue,
			Currency:  planPricing.Currency,
			Type:      "account",
			Status:    "active",
			CreatedAt: now,
			UpdatedAt: now,
			Metadata:  "{\"reason\":\"proration\",\"from_plan\":\"" + plan.ID + "\",\"to_plan\":\"" + newPlanID + "\"}",
		}
		if err := s.repo.CreateCredit(ctx, credit); err != nil {
			s.logger.Error("failed to create proration credit", logger.ErrorField(err))
			return err
		}
	}
	sub.PlanID = newPlanID
	sub.UpdatedAt = now
	return s.repo.UpdateSubscription(ctx, sub)
}

func (s *subscriptionService) GetSubscriptionByID(ctx context.Context, id string) (*domain.Subscription, error) {
	return s.repo.GetSubscriptionByID(ctx, id)
}

func (s *subscriptionService) ListSubscriptions(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.Subscription, int, error) {
	return s.repo.ListSubscriptions(ctx, accountID, status, page, pageSize)
}

func (s *subscriptionService) NextInvoicePreview(ctx context.Context, accountID string) (*domain.Invoice, error) {
	if accountID == "" {
		s.logger.Error("empty account id for invoice preview")
		return nil, domain.NewValidationError("account_id", "must not be empty")
	}
	subs, _, err := s.repo.ListSubscriptions(ctx, accountID, "active", 1, 1)
	if err != nil || len(subs) == 0 {
		s.logger.Error("no active subscription for invoice preview", logger.ErrorField(err))
		return nil, domain.NewValidationError("subscription", "no active subscription")
	}
	sub := subs[0]
	plan, err := s.repo.GetBillingPlanByID(ctx, sub.PlanID)
	if err != nil {
		s.logger.Error("failed to get plan for invoice preview", logger.ErrorField(err))
		return nil, err
	}
	var planPricing struct {
		Price    float64 `json:"price"`
		Currency string  `json:"currency"`
	}
	if err := json.Unmarshal([]byte(plan.Pricing), &planPricing); err != nil {
		s.logger.Error("failed to parse plan pricing JSON", logger.ErrorField(err))
		return nil, domain.NewValidationError("plan_pricing", "invalid pricing JSON")
	}
	amount := planPricing.Price
	credits, _, _ := s.repo.ListCredits(ctx, accountID, "", "active", 1, 100)
	for _, c := range credits {
		if c.Amount > 0 && c.Status == "active" {
			if c.Amount > amount {
				amount = 0
				break
			}
			amount -= c.Amount
		}
	}
	// Apply active discounts (percentage/fixed)
	discounts, _, _ := s.repo.ListDiscounts(ctx, nil, 1, 100)
	for _, d := range discounts {
		if !d.IsActive {
			continue
		}
		if d.Type == "percentage" && d.Value > 0 && d.Value <= 100 {
			amount -= amount * (d.Value / 100)
		} else if d.Type == "fixed" && d.Value > 0 {
			if d.Value > amount {
				amount = 0
			} else {
				amount -= d.Value
			}
		}
		if amount < 0 {
			amount = 0
		}
	}
	// Tax/fee logic (same as CreateInvoice)
	taxRate := 0.0
	if v := viper.GetString("billing.tax_rate"); v != "" {
		if r, err := strconv.ParseFloat(v, 64); err == nil {
			taxRate = r
		}
	}
	fees := []domain.Fee{}
	if v := viper.GetString("billing.fixed_fee"); v != "" {
		if amt, err := strconv.ParseFloat(v, 64); err == nil && amt > 0 {
			fees = append(fees, domain.Fee{Type: "fixed", Amount: amt, Currency: planPricing.Currency})
		}
	}
	if v := viper.GetString("billing.percent_fee"); v != "" {
		if pct, err := strconv.ParseFloat(v, 64); err == nil && pct > 0 {
			fees = append(fees, domain.Fee{Type: "percent", Amount: pct, Currency: planPricing.Currency})
		}
	}
	subtotal := amount
	feeTotal := 0.0
	for _, f := range fees {
		if f.Type == "fixed" {
			feeTotal += f.Amount
		} else if f.Type == "percent" {
			feeTotal += subtotal * (f.Amount / 100)
		}
	}
	taxAmount := (subtotal + feeTotal) * taxRate / 100
	feeBytes, _ := json.Marshal(fees)
	invoice := &domain.Invoice{
		ID:          uuid.NewString(),
		AccountID:   accountID,
		PeriodStart: sub.CurrentPeriodEnd,
		PeriodEnd:   sub.CurrentPeriodEnd.AddDate(0, 1, 0),
		Amount:      subtotal + feeTotal + taxAmount,
		Currency:    planPricing.Currency,
		Status:      "preview",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		LineItems:   plan.Pricing,
		TaxAmount:   taxAmount,
		TaxRate:     taxRate,
		Fees:        string(feeBytes),
	}
	return invoice, nil
}

func (s *subscriptionService) ApplyScheduledPlanChanges(ctx context.Context) error {
	subs, _, err := s.repo.ListSubscriptions(ctx, "", "scheduled", 1, 1000)
	if err != nil {
		s.logger.Error("failed to list scheduled subscriptions", logger.ErrorField(err))
		return err
	}
	now := time.Now().UTC()
	for _, sub := range subs {
		if sub.ScheduledChangeAt != nil && now.After(*sub.ScheduledChangeAt) && sub.ScheduledPlanID != nil {
			sub.PlanID = *sub.ScheduledPlanID
			sub.ScheduledPlanID = nil
			sub.ScheduledChangeAt = nil
			sub.Status = "active"
			sub.UpdatedAt = now
			if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
				s.logger.Error("failed to apply scheduled plan change", logger.ErrorField(err))
				return err
			}
		}
	}
	return nil
}

func (s *subscriptionService) ProcessDunningAndGrace(ctx context.Context) error {
	subs, _, err := s.repo.ListSubscriptions(ctx, "", "dunning", 1, 1000)
	if err != nil {
		s.logger.Error("failed to list dunning subscriptions", logger.ErrorField(err))
		return err
	}
	now := time.Now().UTC()
	for _, sub := range subs {
		if sub.DunningUntil != nil && now.After(*sub.DunningUntil) {
			sub.Status = "canceled"
			sub.CanceledAt = timePtr(now)
			sub.UpdatedAt = now
			if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
				s.logger.Error("failed to cancel after dunning", logger.ErrorField(err))
				return err
			}
		}
	}
	// Grace period logic
	subs, _, err = s.repo.ListSubscriptions(ctx, "", "grace", 1, 1000)
	if err != nil {
		s.logger.Error("failed to list grace subscriptions", logger.ErrorField(err))
		return err
	}
	for _, sub := range subs {
		if sub.GracePeriodEnd != nil && now.After(*sub.GracePeriodEnd) {
			sub.Status = "past_due"
			sub.UpdatedAt = now
			if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
				s.logger.Error("failed to mark past_due after grace", logger.ErrorField(err))
				return err
			}
		}
	}
	return nil
}

func (s *subscriptionService) UpgradeNow(ctx context.Context, id, planID string) error {
	if id == "" || planID == "" {
		s.logger.Error("invalid upgrade now params")
		return domain.NewValidationError("subscription", "id and planID required")
	}
	sub, err := s.repo.GetSubscriptionByID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get subscription for upgrade now", logger.ErrorField(err))
		return err
	}
	if sub.Status != "active" && sub.Status != "trialing" {
		return domain.NewValidationError("subscription", "must be active or trialing to upgrade now")
	}
	if err := s.ProcessProration(ctx, id, planID); err != nil {
		s.logger.Error("failed to process proration for upgrade now", logger.ErrorField(err))
		return err
	}
	oldPlanID := sub.PlanID
	sub.PlanID = planID
	sub.ScheduledPlanID = nil
	sub.ScheduledChangeAt = nil
	sub.Status = "active"
	sub.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpdateSubscription(ctx, sub); err != nil {
		return err
	}
	actorID := "system"
	if v := ctx.Value("actor_id"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			actorID = s
		}
	}
	details := map[string]interface{}{
		"old_plan_id":     oldPlanID,
		"new_plan_id":     planID,
		"subscription_id": id,
		"action":          "upgrade_now",
	}
	detailsJSON, _ := json.Marshal(details)
	log := &domain.AuditLog{
		ID:        uuid.NewString(),
		ActorID:   actorID,
		Action:    "subscription_plan_change",
		TargetID:  id,
		Timestamp: time.Now().UTC(),
		Details:   string(detailsJSON),
	}
	_ = s.repo.CreateAuditLog(ctx, log)
	// Send notification to account email
	acct, err := s.repo.GetBillingAccountByID(ctx, sub.AccountID)
	if err == nil && acct.Email != "" && s.notifications != nil {
		n := &notifications.Notification{
			ID:        uuid.NewString(),
			Type:      "email",
			Recipient: acct.Email,
			Subject:   "Your subscription plan was upgraded",
			Body:      "Your subscription was upgraded from plan " + oldPlanID + " to " + planID + ".",
			Status:    "pending",
			CreatedAt: time.Now().UTC(),
		}
		_ = s.notifications.Send(ctx, n)
	}
	return nil
}

func stringPtr(s string) *string {
	return &s
}
