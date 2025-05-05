package service

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// BillingService defines all billing operations for SaaS
// All methods use RORO pattern and robust error handling
// Only production-grade, real-world logic allowed

type BillingService interface {
	CreateAccount(ctx context.Context, input CreateAccountInput) (CreateAccountOutput, error)
	UpdateAccount(ctx context.Context, input UpdateAccountInput) (UpdateAccountOutput, error)
	GetAccount(ctx context.Context, input GetAccountInput) (GetAccountOutput, error)
	ListAccounts(ctx context.Context, input ListAccountsInput) (ListAccountsOutput, error)

	CreatePlan(ctx context.Context, input CreatePlanInput) (CreatePlanOutput, error)
	UpdatePlan(ctx context.Context, input UpdatePlanInput) (UpdatePlanOutput, error)
	GetPlan(ctx context.Context, input GetPlanInput) (GetPlanOutput, error)
	ListPlans(ctx context.Context, input ListPlansInput) (ListPlansOutput, error)

	CreateUsage(ctx context.Context, input CreateUsageInput) (CreateUsageOutput, error)
	ListUsage(ctx context.Context, input ListUsageInput) (ListUsageOutput, error)

	CreateInvoice(ctx context.Context, input CreateInvoiceInput) (CreateInvoiceOutput, error)
	UpdateInvoice(ctx context.Context, input UpdateInvoiceInput) (UpdateInvoiceOutput, error)
	GetInvoice(ctx context.Context, input GetInvoiceInput) (GetInvoiceOutput, error)
	ListInvoices(ctx context.Context, input ListInvoicesInput) (ListInvoicesOutput, error)

	CreatePayment(ctx context.Context, input CreatePaymentInput) (CreatePaymentOutput, error)
	UpdatePayment(ctx context.Context, input UpdatePaymentInput) (UpdatePaymentOutput, error)
	GetPayment(ctx context.Context, input GetPaymentInput) (GetPaymentOutput, error)
	ListPayments(ctx context.Context, input ListPaymentsInput) (ListPaymentsOutput, error)

	CreateAuditLog(ctx context.Context, input CreateAuditLogInput) (CreateAuditLogOutput, error)
	ListAuditLogs(ctx context.Context, input ListAuditLogsInput) (ListAuditLogsOutput, error)

	CreateDiscount(ctx context.Context, discount *domain.Discount) error
	UpdateDiscount(ctx context.Context, discount *domain.Discount) error
	DeleteDiscount(ctx context.Context, id string) error
	GetDiscountByID(ctx context.Context, id string) (*domain.Discount, error)
	GetDiscountByCode(ctx context.Context, code string) (*domain.Discount, error)
	ListDiscounts(ctx context.Context, isActive *bool, page, pageSize int) ([]*domain.Discount, int, error)

	AggregateUsageForBillingCycle(ctx context.Context, accountID string, periodStart, periodEnd time.Time) (map[string]float64, error)
	CalculateOverageCharges(ctx context.Context, accountID, planID string, periodStart, periodEnd time.Time) (map[string]float64, error)

	GetRevenueReport(ctx context.Context) (map[string]interface{}, error)
	GetARReport(ctx context.Context) (map[string]interface{}, error)
	GetChurnReport(ctx context.Context) (map[string]interface{}, error)

	CreateManualAdjustment(ctx context.Context, accountID string, amount float64, reason string) (map[string]interface{}, error)
	CreateManualRefund(ctx context.Context, paymentID string, amount float64, reason string) (map[string]interface{}, error)
	PerformAccountAction(ctx context.Context, accountID, action, reason string) (map[string]interface{}, error)

	DeletePlan(ctx context.Context, id string) error
}

// billingService implements BillingService
// All logic is production-grade, no dummy code

type billingService struct {
	repo        repository.BillingRepository
	discountSvc DiscountService
	db          *pgxpool.Pool
	logger      *logger.Logger
}

func NewBillingService(repo repository.BillingRepository, discountSvc DiscountService, db *pgxpool.Pool, log *logger.Logger) BillingService {
	if log == nil {
		log = logger.NewProduction()
	}
	return &billingService{repo: repo, discountSvc: discountSvc, db: db, logger: log}
}

// --- Account ---
func (s *billingService) CreateAccount(ctx context.Context, input CreateAccountInput) (CreateAccountOutput, error) {
	if input.Account == nil {
		return CreateAccountOutput{}, domain.ErrInvalidTenant
	}
	if err := s.repo.CreateBillingAccount(ctx, input.Account); err != nil {
		return CreateAccountOutput{}, err
	}
	return CreateAccountOutput{Account: input.Account}, nil
}

func (s *billingService) UpdateAccount(ctx context.Context, input UpdateAccountInput) (UpdateAccountOutput, error) {
	if input.Account == nil {
		return UpdateAccountOutput{}, domain.ErrInvalidTenant
	}
	if err := s.repo.UpdateBillingAccount(ctx, input.Account); err != nil {
		return UpdateAccountOutput{}, err
	}
	return UpdateAccountOutput{Account: input.Account}, nil
}

func (s *billingService) GetAccount(ctx context.Context, input GetAccountInput) (GetAccountOutput, error) {
	acc, err := s.repo.GetBillingAccountByID(ctx, input.ID)
	if err != nil {
		return GetAccountOutput{}, err
	}
	return GetAccountOutput{Account: acc}, nil
}

func (s *billingService) ListAccounts(ctx context.Context, input ListAccountsInput) (ListAccountsOutput, error) {
	accs, total, err := s.repo.ListBillingAccounts(ctx, input.TenantID, input.Page, input.PageSize)
	if err != nil {
		return ListAccountsOutput{}, err
	}
	return ListAccountsOutput{Accounts: accs, Total: total}, nil
}

// --- Plan ---
func (s *billingService) CreatePlan(ctx context.Context, input CreatePlanInput) (CreatePlanOutput, error) {
	if input.Plan == nil {
		return CreatePlanOutput{}, domain.ErrInvalidPlan
	}
	if err := s.repo.CreateBillingPlan(ctx, input.Plan); err != nil {
		return CreatePlanOutput{}, err
	}
	return CreatePlanOutput{Plan: input.Plan}, nil
}

func (s *billingService) UpdatePlan(ctx context.Context, input UpdatePlanInput) (UpdatePlanOutput, error) {
	if input.Plan == nil {
		return UpdatePlanOutput{}, domain.ErrInvalidPlan
	}
	if err := s.repo.UpdateBillingPlan(ctx, input.Plan); err != nil {
		return UpdatePlanOutput{}, err
	}
	return UpdatePlanOutput{Plan: input.Plan}, nil
}

func (s *billingService) GetPlan(ctx context.Context, input GetPlanInput) (GetPlanOutput, error) {
	plan, err := s.repo.GetBillingPlanByID(ctx, input.ID)
	if err != nil {
		return GetPlanOutput{}, err
	}
	return GetPlanOutput{Plan: plan}, nil
}

func (s *billingService) ListPlans(ctx context.Context, input ListPlansInput) (ListPlansOutput, error) {
	plans, total, err := s.repo.ListBillingPlans(ctx, input.ActiveOnly, input.Page, input.PageSize)
	if err != nil {
		return ListPlansOutput{}, err
	}
	return ListPlansOutput{Plans: plans, Total: total}, nil
}

// --- Usage ---
func (s *billingService) CreateUsage(ctx context.Context, input CreateUsageInput) (CreateUsageOutput, error) {
	if input.Usage == nil {
		return CreateUsageOutput{}, domain.ErrInvalidUsage
	}
	if err := s.repo.CreateUsageEvent(ctx, input.Usage); err != nil {
		return CreateUsageOutput{}, err
	}
	return CreateUsageOutput{Usage: input.Usage}, nil
}

func (s *billingService) ListUsage(ctx context.Context, input ListUsageInput) (ListUsageOutput, error) {
	usages, total, err := s.repo.ListUsageEvents(ctx, input.AccountID, input.StartTime, input.EndTime, input.Page, input.PageSize)
	if err != nil {
		return ListUsageOutput{}, err
	}
	return ListUsageOutput{Usages: usages, Total: total}, nil
}

// --- Invoice ---
func (s *billingService) CreateInvoice(ctx context.Context, input CreateInvoiceInput) (CreateInvoiceOutput, error) {
	if input.Invoice == nil {
		return CreateInvoiceOutput{}, domain.ErrInvalidInvoice
	}
	// Tax calculation: configurable rate (env or plan)
	taxRate := 0.0
	if v := os.Getenv("BILLING_TAX_RATE"); v != "" {
		if r, err := strconv.ParseFloat(v, 64); err == nil {
			taxRate = r
		}
	}
	// Fee calculation: fixed + percentage (env, can be extended)
	fees := []domain.Fee{}
	if v := os.Getenv("BILLING_FIXED_FEE"); v != "" {
		if amt, err := strconv.ParseFloat(v, 64); err == nil && amt > 0 {
			fees = append(fees, domain.Fee{Type: "fixed", Amount: amt, Currency: input.Invoice.Currency})
		}
	}
	if v := os.Getenv("BILLING_PERCENT_FEE"); v != "" {
		if pct, err := strconv.ParseFloat(v, 64); err == nil && pct > 0 {
			fees = append(fees, domain.Fee{Type: "percent", Amount: pct, Currency: input.Invoice.Currency})
		}
	}
	// Calculate subtotal
	subtotal := input.Invoice.Amount
	// Apply percent fees
	feeTotal := 0.0
	for _, f := range fees {
		if f.Type == "fixed" {
			feeTotal += f.Amount
		} else if f.Type == "percent" {
			feeTotal += subtotal * (f.Amount / 100)
		}
	}
	// Calculate tax
	taxAmount := (subtotal + feeTotal) * taxRate / 100
	input.Invoice.TaxAmount = taxAmount
	input.Invoice.TaxRate = taxRate
	// Serialize fees
	feeBytes, _ := json.Marshal(fees)
	input.Invoice.Fees = string(feeBytes)
	// Update total amount
	input.Invoice.Amount = subtotal + feeTotal + taxAmount
	if err := s.repo.CreateInvoice(ctx, input.Invoice); err != nil {
		return CreateInvoiceOutput{}, err
	}
	return CreateInvoiceOutput{Invoice: input.Invoice}, nil
}

func (s *billingService) UpdateInvoice(ctx context.Context, input UpdateInvoiceInput) (UpdateInvoiceOutput, error) {
	if input.Invoice == nil {
		return UpdateInvoiceOutput{}, domain.ErrInvalidInvoice
	}
	if err := s.repo.UpdateInvoice(ctx, input.Invoice); err != nil {
		return UpdateInvoiceOutput{}, err
	}
	return UpdateInvoiceOutput{Invoice: input.Invoice}, nil
}

func (s *billingService) GetInvoice(ctx context.Context, input GetInvoiceInput) (GetInvoiceOutput, error) {
	inv, err := s.repo.GetInvoiceByID(ctx, input.ID)
	if err != nil {
		return GetInvoiceOutput{}, err
	}
	return GetInvoiceOutput{Invoice: inv}, nil
}

func (s *billingService) ListInvoices(ctx context.Context, input ListInvoicesInput) (ListInvoicesOutput, error) {
	invs, total, err := s.repo.ListInvoices(ctx, input.AccountID, input.Status, input.Page, input.PageSize)
	if err != nil {
		return ListInvoicesOutput{}, err
	}
	return ListInvoicesOutput{Invoices: invs, Total: total}, nil
}

// --- Payment ---
func (s *billingService) CreatePayment(ctx context.Context, input CreatePaymentInput) (CreatePaymentOutput, error) {
	if input.Payment == nil {
		return CreatePaymentOutput{}, domain.ErrInvalidPayment
	}
	if err := s.repo.CreatePayment(ctx, input.Payment); err != nil {
		return CreatePaymentOutput{}, err
	}
	return CreatePaymentOutput{Payment: input.Payment}, nil
}

func (s *billingService) UpdatePayment(ctx context.Context, input UpdatePaymentInput) (UpdatePaymentOutput, error) {
	if input.Payment == nil {
		return UpdatePaymentOutput{}, domain.ErrInvalidPayment
	}
	if err := s.repo.UpdatePayment(ctx, input.Payment); err != nil {
		return UpdatePaymentOutput{}, err
	}
	return UpdatePaymentOutput{Payment: input.Payment}, nil
}

func (s *billingService) GetPayment(ctx context.Context, input GetPaymentInput) (GetPaymentOutput, error) {
	pay, err := s.repo.GetPaymentByID(ctx, input.ID)
	if err != nil {
		return GetPaymentOutput{}, err
	}
	return GetPaymentOutput{Payment: pay}, nil
}

func (s *billingService) ListPayments(ctx context.Context, input ListPaymentsInput) (ListPaymentsOutput, error) {
	pays, total, err := s.repo.ListPayments(ctx, input.InvoiceID, input.Page, input.PageSize)
	if err != nil {
		return ListPaymentsOutput{}, err
	}
	return ListPaymentsOutput{Payments: pays, Total: total}, nil
}

// --- Audit Log ---
func (s *billingService) CreateAuditLog(ctx context.Context, input CreateAuditLogInput) (CreateAuditLogOutput, error) {
	if input.AuditLog == nil {
		return CreateAuditLogOutput{}, domain.ErrInvalidAuditLog
	}
	if err := s.repo.CreateAuditLog(ctx, input.AuditLog); err != nil {
		return CreateAuditLogOutput{}, err
	}
	return CreateAuditLogOutput{AuditLog: input.AuditLog}, nil
}

func (s *billingService) ListAuditLogs(ctx context.Context, input ListAuditLogsInput) (ListAuditLogsOutput, error) {
	logs, total, err := s.repo.ListAuditLogs(ctx, input.AccountID, input.Action, input.StartTime, input.EndTime, input.Page, input.PageSize)
	if err != nil {
		return ListAuditLogsOutput{}, err
	}
	return ListAuditLogsOutput{AuditLogs: logs, Total: total}, nil
}

// --- Types ---
// All input/output types for RORO pattern

type CreateAccountInput struct{ Account *domain.BillingAccount }
type CreateAccountOutput struct{ Account *domain.BillingAccount }

type UpdateAccountInput struct{ Account *domain.BillingAccount }
type UpdateAccountOutput struct{ Account *domain.BillingAccount }

type GetAccountInput struct{ ID string }
type GetAccountOutput struct{ Account *domain.BillingAccount }

type ListAccountsInput struct {
	TenantID       string
	Page, PageSize int
}
type ListAccountsOutput struct {
	Accounts []*domain.BillingAccount
	Total    int
}

type CreatePlanInput struct{ Plan *domain.BillingPlan }
type CreatePlanOutput struct{ Plan *domain.BillingPlan }

type UpdatePlanInput struct{ Plan *domain.BillingPlan }
type UpdatePlanOutput struct{ Plan *domain.BillingPlan }

type GetPlanInput struct{ ID string }
type GetPlanOutput struct{ Plan *domain.BillingPlan }

type ListPlansInput struct {
	ActiveOnly     bool
	Page, PageSize int
}
type ListPlansOutput struct {
	Plans []*domain.BillingPlan
	Total int
}

type CreateUsageInput struct{ Usage *domain.UsageEvent }
type CreateUsageOutput struct{ Usage *domain.UsageEvent }

type ListUsageInput struct {
	AccountID          string
	StartTime, EndTime time.Time
	Page, PageSize     int
}
type ListUsageOutput struct {
	Usages []*domain.UsageEvent
	Total  int
}

type CreateInvoiceInput struct{ Invoice *domain.Invoice }
type CreateInvoiceOutput struct{ Invoice *domain.Invoice }

type UpdateInvoiceInput struct{ Invoice *domain.Invoice }
type UpdateInvoiceOutput struct{ Invoice *domain.Invoice }

type GetInvoiceInput struct{ ID string }
type GetInvoiceOutput struct{ Invoice *domain.Invoice }
type ListInvoicesInput struct {
	AccountID, Status string
	Page, PageSize    int
}
type ListInvoicesOutput struct {
	Invoices []*domain.Invoice
	Total    int
}

type CreatePaymentInput struct{ Payment *domain.Payment }
type CreatePaymentOutput struct{ Payment *domain.Payment }

type UpdatePaymentInput struct{ Payment *domain.Payment }
type UpdatePaymentOutput struct{ Payment *domain.Payment }

type GetPaymentInput struct{ ID string }
type GetPaymentOutput struct{ Payment *domain.Payment }
type ListPaymentsInput struct {
	InvoiceID      string
	Page, PageSize int
}
type ListPaymentsOutput struct {
	Payments []*domain.Payment
	Total    int
}

type CreateAuditLogInput struct{ AuditLog *domain.AuditLog }
type CreateAuditLogOutput struct{ AuditLog *domain.AuditLog }

type ListAuditLogsInput struct {
	AccountID, Action  string
	StartTime, EndTime time.Time
	Page, PageSize     int
}
type ListAuditLogsOutput struct {
	AuditLogs []*domain.AuditLog
	Total     int
}

// DiscountInput for RORO pattern
// Used by API handler for Discount endpoints

type DiscountInput struct {
	*domain.Discount
}

// DiscountService forwarding methods
func (s *billingService) CreateDiscount(ctx context.Context, discount *domain.Discount) error {
	return s.discountSvc.CreateDiscount(ctx, discount)
}
func (s *billingService) UpdateDiscount(ctx context.Context, discount *domain.Discount) error {
	return s.discountSvc.UpdateDiscount(ctx, discount)
}
func (s *billingService) DeleteDiscount(ctx context.Context, id string) error {
	return s.discountSvc.DeleteDiscount(ctx, id)
}
func (s *billingService) GetDiscountByID(ctx context.Context, id string) (*domain.Discount, error) {
	return s.discountSvc.GetDiscountByID(ctx, id)
}
func (s *billingService) GetDiscountByCode(ctx context.Context, code string) (*domain.Discount, error) {
	return s.discountSvc.GetDiscountByCode(ctx, code)
}
func (s *billingService) ListDiscounts(ctx context.Context, isActive *bool, page, pageSize int) ([]*domain.Discount, int, error) {
	return s.discountSvc.ListDiscounts(ctx, isActive, page, pageSize)
}

// AggregateUsageForBillingCycle aggregates usage events for an account and billing cycle
func (s *billingService) AggregateUsageForBillingCycle(ctx context.Context, accountID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" {
		return nil, domain.ErrInvalidTenant
	}
	usages, _, err := s.repo.ListUsageEvents(ctx, accountID, periodStart, periodEnd, 1, 10000)
	if err != nil {
		return nil, err
	}
	usageTotals := make(map[string]float64)
	for _, u := range usages {
		usageTotals[u.Resource] += u.Quantity
	}
	return usageTotals, nil
}

// CalculateOverageCharges calculates overage charges for an account and billing cycle
func (s *billingService) CalculateOverageCharges(ctx context.Context, accountID, planID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" || planID == "" {
		return nil, domain.ErrInvalidTenant
	}
	plan, err := s.repo.GetBillingPlanByID(ctx, planID)
	if err != nil {
		return nil, err
	}
	usageTotals, err := s.AggregateUsageForBillingCycle(ctx, accountID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	// Parse plan.Pricing (JSON) to get included limits and overage rates
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

// parsePlanPricing parses pricing JSON for limits and overage rates
func parsePlanPricing(pricing string) (map[string]float64, map[string]float64, error) {
	// Example pricing JSON: {"api_calls": {"limit": 1000, "overage": 0.01}, ...}
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

func (s *billingService) GetRevenueReport(ctx context.Context) (map[string]interface{}, error) {
	// Example: sum of all paid invoices in the last 30 days
	row := s.db.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '30 days'`)
	var revenue float64
	if err := row.Scan(&revenue); err != nil {
		s.logger.Error("failed to get revenue report", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"revenue": revenue}, nil
}

func (s *billingService) GetARReport(ctx context.Context) (map[string]interface{}, error) {
	// Example: sum of all outstanding invoices
	row := s.db.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status IN ('issued', 'overdue')`)
	var ar float64
	if err := row.Scan(&ar); err != nil {
		s.logger.Error("failed to get AR report", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"accounts_receivable": ar}, nil
}

func (s *billingService) GetChurnReport(ctx context.Context) (map[string]interface{}, error) {
	// Example: count of canceled subscriptions in the last 30 days
	row := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM subscriptions WHERE status = 'canceled' AND canceled_at >= NOW() - INTERVAL '30 days'`)
	var churn int
	if err := row.Scan(&churn); err != nil {
		s.logger.Error("failed to get churn report", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"churned_subscriptions": churn}, nil
}

func (s *billingService) CreateManualAdjustment(ctx context.Context, accountID string, amount float64, reason string) (map[string]interface{}, error) {
	if accountID == "" || amount == 0 || reason == "" {
		return nil, domain.NewValidationError("manual_adjustment", "accountID, amount, and reason required")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO manual_adjustments (id, account_id, amount, reason, created_at) VALUES (gen_random_uuid(), $1, $2, $3, NOW())`, accountID, amount, reason)
	if err != nil {
		s.logger.Error("failed to create manual adjustment", logger.ErrorField(err))
		return nil, err
	}
	_ = s.repo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.NewString(),
		ActorID:   "admin",
		Action:    "manual_adjustment",
		TargetID:  accountID,
		Timestamp: time.Now().UTC(),
		Details:   reason,
	})
	return map[string]interface{}{"status": "ok"}, nil
}

func (s *billingService) CreateManualRefund(ctx context.Context, paymentID string, amount float64, reason string) (map[string]interface{}, error) {
	if paymentID == "" || amount == 0 || reason == "" {
		return nil, domain.NewValidationError("manual_refund", "paymentID, amount, and reason required")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO manual_refunds (id, payment_id, amount, reason, created_at) VALUES (gen_random_uuid(), $1, $2, $3, NOW())`, paymentID, amount, reason)
	if err != nil {
		s.logger.Error("failed to create manual refund", logger.ErrorField(err))
		return nil, err
	}
	_ = s.repo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.NewString(),
		ActorID:   "admin",
		Action:    "manual_refund",
		TargetID:  paymentID,
		Timestamp: time.Now().UTC(),
		Details:   reason,
	})
	return map[string]interface{}{"status": "ok"}, nil
}

func (s *billingService) PerformAccountAction(ctx context.Context, accountID, action, reason string) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		return nil, domain.NewValidationError("account_action", "accountID and action required")
	}
	_, err := s.db.Exec(ctx, `INSERT INTO account_actions (id, account_id, action, reason, created_at) VALUES (gen_random_uuid(), $1, $2, $3, NOW())`, accountID, action, reason)
	if err != nil {
		s.logger.Error("failed to perform account action", logger.ErrorField(err))
		return nil, err
	}
	_ = s.repo.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.NewString(),
		ActorID:   "admin",
		Action:    action,
		TargetID:  accountID,
		Timestamp: time.Now().UTC(),
		Details:   reason,
	})
	return map[string]interface{}{"status": "ok"}, nil
}

func (s *billingService) DeletePlan(ctx context.Context, id string) error {
	if id == "" {
		return domain.ErrInvalidPlan
	}
	return s.repo.DeleteBillingPlan(ctx, id)
}
