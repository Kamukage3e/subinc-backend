package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"time"

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