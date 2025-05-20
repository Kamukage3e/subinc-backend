package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// --- Plan CRUD ---
func (s *PostgresStore) CreatePlan(ctx context.Context, p Plan) (Plan, error) {
	const q = `INSERT INTO plans (id, name, description, price, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, description, price, active, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, p.ID, p.Name, p.Description, p.Price, p.Active, p.CreatedAt, p.UpdatedAt)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreatePlan failed", logger.ErrorField(err), logger.Any("plan", p))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPlan(ctx context.Context, id string) (Plan, error) {
	const q = `SELECT id, name, description, price, active, created_at, updated_at FROM plans WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			logger.LogWarn("GetPlan: not found", logger.String("id", id))
			return Plan{}, errors.New("no rows")
		}
		logger.LogError("GetPlan failed", logger.ErrorField(err), logger.String("id", id))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdatePlan(ctx context.Context, p Plan) (Plan, error) {
	const q = `UPDATE plans SET name = $2, description = $3, price = $4, active = $5, updated_at = $6 WHERE id = $1 RETURNING id, name, description, price, active, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, p.ID, p.Name, p.Description, p.Price, p.Active, p.UpdatedAt)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("UpdatePlan failed", logger.ErrorField(err), logger.Any("plan", p))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPlans(ctx context.Context, activeOnly bool, page, pageSize int) ([]Plan, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, name, description, price, active, created_at, updated_at FROM plans`
	args := []interface{}{}
	if activeOnly {
		q += " WHERE active = true"
	}
	q += " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListPlans query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Active, &p.CreatedAt, &p.UpdatedAt); err != nil {
			logger.LogError("ListPlans scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *PostgresStore) DeletePlan(ctx context.Context, id string) error {
	const q = `DELETE FROM plans WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	return err
}

// --- Usage CRUD ---
func (s *PostgresStore) CreateUsage(ctx context.Context, u Usage) (Usage, error) {
	const q = `INSERT INTO usage (id, account_id, metric, amount, period, created_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, account_id, metric, amount, period, created_at`
	row := s.DB.QueryRow(ctx, q, u.ID, u.AccountID, u.Metric, u.Amount, u.Period, u.CreatedAt)
	var out Usage
	if err := row.Scan(&out.ID, &out.AccountID, &out.Metric, &out.Amount, &out.Period, &out.CreatedAt); err != nil {
		logger.LogError("CreateUsage failed", logger.ErrorField(err), logger.Any("usage", u))
		return Usage{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListUsage(ctx context.Context, accountID, metric, period string, page, pageSize int) ([]Usage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, metric, amount, period, created_at FROM usage WHERE account_id = $1`
	args := []interface{}{accountID}
	if metric != "" {
		q += " AND metric = $2"
		args = append(args, metric)
	}
	if period != "" {
		q += " AND period = $3"
		args = append(args, period)
	}
	q += " ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListUsage query failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.ID, &u.AccountID, &u.Metric, &u.Amount, &u.Period, &u.CreatedAt); err != nil {
			logger.LogError("ListUsage scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// --- Usage Aggregation/Overage ---
func (s *PostgresStore) AggregateUsageForBillingCycle(ctx context.Context, accountID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" {
		return nil, NewValidationError("account_id", "must not be empty")
	}
	rows, err := s.DB.Query(ctx, `SELECT metric, SUM(amount) FROM usage WHERE account_id = $1 AND created_at >= $2 AND created_at <= $3 GROUP BY metric`, accountID, periodStart, periodEnd)
	if err != nil {
		logger.LogError("AggregateUsageForBillingCycle failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	usageTotals := make(map[string]float64)
	for rows.Next() {
		var metric string
		var total float64
		if err := rows.Scan(&metric, &total); err != nil {
			logger.LogError("AggregateUsageForBillingCycle scan failed", logger.ErrorField(err))
			return nil, err
		}
		usageTotals[metric] = total
	}
	return usageTotals, nil
}

func (s *PostgresStore) CalculateOverageCharges(ctx context.Context, accountID, planID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" || planID == "" {
		return nil, NewValidationError("overage", "accountID and planID required")
	}
	plan, err := s.GetPlan(ctx, planID)
	if err != nil {
		logger.LogError("CalculateOverageCharges: GetPlan failed", logger.ErrorField(err))
		return nil, err
	}
	usageTotals, err := s.AggregateUsageForBillingCycle(ctx, accountID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	limits, overages, err := parsePlanPricing(plan.Pricing)
	if err != nil {
		return nil, err
	}
	overageCharges := make(map[string]float64)
	for resource, used := range usageTotals {
		limit := limits[resource]
		rate := overages[resource]
		if used > limit && rate > 0 {
			overageCharges[resource] = (used - limit) * rate
		}
	}
	return overageCharges, nil
}

// --- Plan Pricing Parsing ---
func parsePlanPricing(pricing string) (map[string]float64, map[string]float64, error) {
	var raw map[string]map[string]float64
	err := json.Unmarshal([]byte(pricing), &raw)
	if err != nil {
		return nil, nil, err
	}
	limits := make(map[string]float64)
	overages := make(map[string]float64)
	for k, v := range raw {
		limits[k] = v["limit"]
		overages[k] = v["overage"]
	}
	return limits, overages, nil
}

// --- Subscription CRUD ---
func (s *PostgresStore) CreateSubscription(ctx context.Context, sub Subscription) (Subscription, error) {
	const q = `INSERT INTO subscriptions (
		id, account_id, plan_id, status, currency, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
	) RETURNING id, account_id, plan_id, status, currency, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q,
		sub.ID, sub.AccountID, sub.PlanID, sub.Status, sub.Currency, sub.TrialStart, sub.TrialEnd, sub.CurrentPeriodStart, sub.CurrentPeriodEnd, sub.CancelAt, sub.CanceledAt, sub.GracePeriodEnd, sub.DunningUntil, sub.ScheduledPlanID, sub.ScheduledChangeAt, sub.CreatedAt, sub.UpdatedAt, sub.Metadata,
	)
	var out Subscription
	err := row.Scan(
		&out.ID, &out.AccountID, &out.PlanID, &out.Status, &out.Currency, &out.TrialStart, &out.TrialEnd, &out.CurrentPeriodStart, &out.CurrentPeriodEnd, &out.CancelAt, &out.CanceledAt, &out.GracePeriodEnd, &out.DunningUntil, &out.ScheduledPlanID, &out.ScheduledChangeAt, &out.CreatedAt, &out.UpdatedAt, &out.Metadata,
	)
	if err != nil {
		logger.LogError("CreateSubscription failed", logger.ErrorField(err), logger.Any("sub", sub))
		return Subscription{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateSubscription(ctx context.Context, sub Subscription) (Subscription, error) {
	const q = `UPDATE subscriptions SET
		plan_id = $2, status = $3, currency = $4, trial_start = $5, trial_end = $6, current_period_start = $7, current_period_end = $8, cancel_at = $9, canceled_at = $10, grace_period_end = $11, dunning_until = $12, scheduled_plan_id = $13, scheduled_change_at = $14, updated_at = $15, metadata = $16
	WHERE id = $1
	RETURNING id, account_id, plan_id, status, currency, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q,
		sub.ID, sub.PlanID, sub.Status, sub.Currency, sub.TrialStart, sub.TrialEnd, sub.CurrentPeriodStart, sub.CurrentPeriodEnd, sub.CancelAt, sub.CanceledAt, sub.GracePeriodEnd, sub.DunningUntil, sub.ScheduledPlanID, sub.ScheduledChangeAt, sub.UpdatedAt, sub.Metadata,
	)
	var out Subscription
	err := row.Scan(
		&out.ID, &out.AccountID, &out.PlanID, &out.Status, &out.Currency, &out.TrialStart, &out.TrialEnd, &out.CurrentPeriodStart, &out.CurrentPeriodEnd, &out.CancelAt, &out.CanceledAt, &out.GracePeriodEnd, &out.DunningUntil, &out.ScheduledPlanID, &out.ScheduledChangeAt, &out.CreatedAt, &out.UpdatedAt, &out.Metadata,
	)
	if err != nil {
		logger.LogError("UpdateSubscription failed", logger.ErrorField(err), logger.Any("sub", sub))
		return Subscription{}, err
	}
	return out, nil
}

func (s *PostgresStore) PatchSubscription(ctx context.Context, id, action string) error {
	// Only allow specific actions for patch
	switch action {
	case "pause":
		const q = `UPDATE subscriptions SET status = 'paused', updated_at = $2 WHERE id = $1`
		_, err := s.DB.Exec(ctx, q, id, time.Now().UTC())
		if err != nil {
			logger.LogError("PatchSubscription: pause failed", logger.ErrorField(err), logger.String("id", id))
			return err
		}
		return nil
	case "reactivate":
		const q = `UPDATE subscriptions SET status = 'active', updated_at = $2 WHERE id = $1`
		_, err := s.DB.Exec(ctx, q, id, time.Now().UTC())
		if err != nil {
			logger.LogError("PatchSubscription: reactivate failed", logger.ErrorField(err), logger.String("id", id))
			return err
		}
		return nil
	default:
		return errors.New("unsupported patch action")
	}
}

func (s *PostgresStore) DeleteSubscription(ctx context.Context, id string) error {
	const q = `DELETE FROM subscriptions WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteSubscription failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

func (s *PostgresStore) GetSubscription(ctx context.Context, id string) (Subscription, error) {
	const q = `SELECT id, account_id, plan_id, status, currency, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata FROM subscriptions WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Subscription
	err := row.Scan(
		&out.ID, &out.AccountID, &out.PlanID, &out.Status, &out.Currency, &out.TrialStart, &out.TrialEnd, &out.CurrentPeriodStart, &out.CurrentPeriodEnd, &out.CancelAt, &out.CanceledAt, &out.GracePeriodEnd, &out.DunningUntil, &out.ScheduledPlanID, &out.ScheduledChangeAt, &out.CreatedAt, &out.UpdatedAt, &out.Metadata,
	)
	if err != nil {
		logger.LogError("GetSubscription failed", logger.ErrorField(err), logger.String("id", id))
		return Subscription{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListSubscriptions(ctx context.Context, accountID, status string, page, pageSize int) ([]Subscription, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, plan_id, status, currency, trial_start, trial_end, current_period_start, current_period_end, cancel_at, canceled_at, grace_period_end, dunning_until, scheduled_plan_id, scheduled_change_at, created_at, updated_at, metadata FROM subscriptions WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if accountID != "" {
		q += " AND account_id = $" + itoa(argIdx)
		args = append(args, accountID)
		argIdx++
	}
	if status != "" {
		q += " AND status = $" + itoa(argIdx)
		args = append(args, status)
		argIdx++
	}
	q += " ORDER BY created_at DESC LIMIT $" + itoa(argIdx) + " OFFSET $" + itoa(argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListSubscriptions query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		var sub Subscription
		err := rows.Scan(
			&sub.ID, &sub.AccountID, &sub.PlanID, &sub.Status, &sub.Currency, &sub.TrialStart, &sub.TrialEnd, &sub.CurrentPeriodStart, &sub.CurrentPeriodEnd, &sub.CancelAt, &sub.CanceledAt, &sub.GracePeriodEnd, &sub.DunningUntil, &sub.ScheduledPlanID, &sub.ScheduledChangeAt, &sub.CreatedAt, &sub.UpdatedAt, &sub.Metadata,
		)
		if err != nil {
			logger.LogError("ListSubscriptions scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, sub)
	}
	return out, nil
}

func (s *PostgresStore) ChangePlanSubscription(ctx context.Context, id, planID string) error {
	// Start a transaction to handle the plan change atomically
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		logger.LogError("ChangePlanSubscription begin transaction failed", logger.ErrorField(err))
		return err
	}
	defer tx.Rollback(ctx)

	// First, get the current subscription details
	var subscription Subscription
	const getQ = `SELECT id, account_id, plan_id, status, currency, current_period_start, current_period_end, created_at 
		FROM subscriptions WHERE id = $1 FOR UPDATE`

	err = tx.QueryRow(ctx, getQ, id).Scan(
		&subscription.ID, &subscription.AccountID, &subscription.PlanID,
		&subscription.Status, &subscription.Currency,
		&subscription.CurrentPeriodStart, &subscription.CurrentPeriodEnd,
		&subscription.CreatedAt,
	)
	if err != nil {
		logger.LogError("ChangePlanSubscription get subscription failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	// Get the old plan to calculate proration
	var oldPlanPrice float64
	const oldPlanQ = `SELECT price FROM plans WHERE id = $1`
	err = tx.QueryRow(ctx, oldPlanQ, subscription.PlanID).Scan(&oldPlanPrice)
	if err != nil {
		logger.LogError("ChangePlanSubscription get old plan failed", logger.ErrorField(err), logger.String("planID", subscription.PlanID))
		return err
	}

	// Get the new plan details
	var newPlanPrice float64
	const newPlanQ = `SELECT price FROM plans WHERE id = $1`
	err = tx.QueryRow(ctx, newPlanQ, planID).Scan(&newPlanPrice)
	if err != nil {
		logger.LogError("ChangePlanSubscription get new plan failed", logger.ErrorField(err), logger.String("planID", planID))
		return err
	}

	// Calculate proration
	now := time.Now().UTC()
	totalPeriodDuration := subscription.CurrentPeriodEnd.Sub(subscription.CurrentPeriodStart)
	remainingDuration := subscription.CurrentPeriodEnd.Sub(now)
	remainingRatio := float64(remainingDuration) / float64(totalPeriodDuration)

	// Credit for unused portion of old plan
	unusedAmount := oldPlanPrice * remainingRatio

	// Charge for remaining time on new plan
	newChargeAmount := newPlanPrice * remainingRatio

	// Calculate net adjustment (positive means charge more, negative means refund)
	proratedAdjustment := newChargeAmount - unusedAmount

	// Update the subscription with the new plan
	const updateQ = `UPDATE subscriptions 
		SET plan_id = $2, 
			updated_at = $3
		WHERE id = $1`

	_, err = tx.Exec(ctx, updateQ, id, planID, now)
	if err != nil {
		logger.LogError("ChangePlanSubscription update failed", logger.ErrorField(err), logger.String("id", id), logger.String("planID", planID))
		return err
	}

	// Record the proration adjustment as a transaction
	if proratedAdjustment != 0 {
		const prorateQ = `INSERT INTO subscription_adjustments (
			id, subscription_id, account_id, amount, currency, reason, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`

		adjustmentID := uuid.New().String()
		reason := fmt.Sprintf("Plan change proration: %s to %s", subscription.PlanID, planID)

		_, err = tx.Exec(ctx, prorateQ, adjustmentID, id, subscription.AccountID,
			proratedAdjustment, subscription.Currency, reason, now)

		if err != nil {
			logger.LogError("ChangePlanSubscription record proration failed",
				logger.ErrorField(err),
				logger.String("id", id),
				logger.Float64("adjustment", proratedAdjustment))
			return err
		}
	}

	// Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		logger.LogError("ChangePlanSubscription commit failed", logger.ErrorField(err))
		return err
	}

	return nil
}

func (s *PostgresStore) CancelSubscriptionNow(ctx context.Context, id string) error {
	const q = `UPDATE subscriptions SET status = 'canceled', canceled_at = $2, updated_at = $2 WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id, time.Now().UTC())
	if err != nil {
		logger.LogError("CancelSubscriptionNow failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

func (s *PostgresStore) ResumeSubscription(ctx context.Context, id string) error {
	const q = `UPDATE subscriptions SET status = 'active', updated_at = $2 WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id, time.Now().UTC())
	if err != nil {
		logger.LogError("ResumeSubscription failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

func (s *PostgresStore) UpgradeNowSubscription(ctx context.Context, id, planID string) error {
	const q = `UPDATE subscriptions SET plan_id = $2, status = 'active', updated_at = $3 WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id, planID, time.Now().UTC())
	if err != nil {
		logger.LogError("UpgradeNowSubscription failed", logger.ErrorField(err), logger.String("id", id), logger.String("planID", planID))
		return err
	}
	return nil
}

// ProcessAutoRenewals handles automatic renewal of active subscriptions that are due
func (s *PostgresStore) ProcessAutoRenewals(ctx context.Context) error {
	// Find subscriptions that are about to expire (within the next 24 hours)
	now := time.Now().UTC()
	renewalCutoff := now.Add(24 * time.Hour)

	// Query for subscriptions that need renewal
	const q = `
		SELECT id, account_id, plan_id, currency, current_period_start, current_period_end 
		FROM subscriptions 
		WHERE status = 'active' 
		AND current_period_end <= $1
		AND (canceled_at IS NULL OR canceled_at > current_period_end)
		AND (NOT EXISTS (
			SELECT 1 FROM subscription_renewals 
			WHERE subscription_id = subscriptions.id 
			AND renewal_period_end = subscriptions.current_period_end
		))
	`

	rows, err := s.DB.Query(ctx, q, renewalCutoff)
	if err != nil {
		logger.LogError("ProcessAutoRenewals query failed", logger.ErrorField(err))
		return err
	}
	defer rows.Close()

	// Process each subscription that needs renewal
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(
			&sub.ID, &sub.AccountID, &sub.PlanID, &sub.Currency,
			&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		); err != nil {
			logger.LogError("ProcessAutoRenewals scan failed", logger.ErrorField(err))
			continue
		}

		// Process this subscription renewal in a separate transaction
		if err := s.renewSubscription(ctx, sub); err != nil {
			logger.LogError("ProcessAutoRenewals failed for subscription",
				logger.ErrorField(err),
				logger.String("subscription_id", sub.ID),
				logger.String("account_id", sub.AccountID))
			// Continue with other subscriptions even if this one fails
			continue
		}

		logger.LogInfo("Subscription successfully renewed",
			logger.String("subscription_id", sub.ID),
			logger.String("account_id", sub.AccountID))
	}

	return nil
}

// renewSubscription handles the renewal of a single subscription
func (s *PostgresStore) renewSubscription(ctx context.Context, sub Subscription) error {
	// Start a transaction for this renewal process
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		logger.LogError("renewSubscription begin transaction failed", logger.ErrorField(err))
		return err
	}
	defer tx.Rollback(ctx)

	// 1. Get the current plan details
	var plan Plan
	const planQuery = `SELECT id, name, price, currency FROM plans WHERE id = $1`

	err = tx.QueryRow(ctx, planQuery, sub.PlanID).Scan(
		&plan.ID, &plan.Name, &plan.Price, &plan.Currency,
	)
	if err != nil {
		logger.LogError("renewSubscription get plan failed",
			logger.ErrorField(err),
			logger.String("plan_id", sub.PlanID))
		return err
	}

	// 2. Calculate the next billing period
	periodDuration := sub.CurrentPeriodEnd.Sub(sub.CurrentPeriodStart)
	newPeriodStart := sub.CurrentPeriodEnd
	newPeriodEnd := newPeriodStart.Add(periodDuration)

	// 3. Create an invoice for the renewal
	invoiceID := uuid.New().String()
	now := time.Now().UTC()

	const createInvoiceQuery = `
		INSERT INTO invoices (
			id, account_id, subscription_id, amount, currency, status, 
			due_date, created_at, updated_at, description
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`

	description := fmt.Sprintf("Subscription renewal for plan: %s", plan.Name)

	_, err = tx.Exec(ctx, createInvoiceQuery,
		invoiceID, sub.AccountID, sub.ID, plan.Price, plan.Currency,
		"pending", newPeriodStart, now, now, description,
	)

	if err != nil {
		logger.LogError("renewSubscription create invoice failed",
			logger.ErrorField(err),
			logger.String("subscription_id", sub.ID))
		return err
	}

	// 4. Update the subscription with the new billing period
	const updateSubQuery = `
		UPDATE subscriptions 
		SET current_period_start = $1, 
			current_period_end = $2, 
			updated_at = $3
		WHERE id = $4
	`

	_, err = tx.Exec(ctx, updateSubQuery,
		newPeriodStart, newPeriodEnd, now, sub.ID)

	if err != nil {
		logger.LogError("renewSubscription update subscription failed",
			logger.ErrorField(err),
			logger.String("subscription_id", sub.ID))
		return err
	}

	// 5. Record the renewal attempt
	const recordRenewalQuery = `
		INSERT INTO subscription_renewals (
			id, subscription_id, account_id, invoice_id,
			renewal_period_start, renewal_period_end, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)
	`

	renewalID := uuid.New().String()

	_, err = tx.Exec(ctx, recordRenewalQuery,
		renewalID, sub.ID, sub.AccountID, invoiceID,
		newPeriodStart, newPeriodEnd, now)

	if err != nil {
		logger.LogError("renewSubscription record renewal failed",
			logger.ErrorField(err),
			logger.String("subscription_id", sub.ID))
		return err
	}

	// 6. Commit the transaction
	if err = tx.Commit(ctx); err != nil {
		logger.LogError("renewSubscription commit failed", logger.ErrorField(err))
		return err
	}

	return nil
}

// --- SubscriptionPluginConfig CRUD ---
func (s *PostgresStore) SetSubscriptionPluginConfig(ctx context.Context, tenantID, pluginName string) (SubscriptionPluginConfig, error) {
	if tenantID == "" {
		return SubscriptionPluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		return SubscriptionPluginConfig{}, NewValidationError("plugin_name", "must not be empty")
	}
	updatedAt := time.Now().UTC()
	const q = `INSERT INTO subscription_plugin_config (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET plugin_name = $2, updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at`
	row := s.DB.QueryRow(ctx, q, tenantID, pluginName, updatedAt)
	var out SubscriptionPluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("SetSubscriptionPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return SubscriptionPluginConfig{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetSubscriptionPluginConfig(ctx context.Context, tenantID string) (SubscriptionPluginConfig, error) {
	if tenantID == "" {
		return SubscriptionPluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	const q = `SELECT tenant_id, plugin_name, updated_at FROM subscription_plugin_config WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var out SubscriptionPluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("GetSubscriptionPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return SubscriptionPluginConfig{}, err
	}
	return out, nil
}

// Helper for dynamic SQL arg numbering
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
