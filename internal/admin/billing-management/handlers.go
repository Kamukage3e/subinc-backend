package billing_management

import (
	"time"

	"encoding/json"

	"github.com/gofiber/fiber/v2"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type BillingAdminHandler struct {
	AccountService             AccountService
	PlanService                PlanService
	UsageService               UsageService
	InvoiceService             InvoiceService
	PaymentService             PaymentService
	DiscountService            DiscountService
	CouponService              CouponService
	CreditService              CreditService
	RefundService              RefundService
	PaymentMethodService       PaymentMethodService
	SubscriptionService        SubscriptionService
	WebhookEventService        WebhookEventService
	InvoiceAdjustmentService   InvoiceAdjustmentService
	ManualAdjustmentService    ManualAdjustmentService
	ManualRefundService        ManualRefundService
	AccountActionService       AccountActionService
	WebhookSubscriptionService WebhookSubscriptionService
	TaxInfoService             TaxInfoService
	Store                      *PostgresStore
	AuditLogger                BillingAuditLogger // use interface for audit logging
}

// Helper to serialize details to string for audit logs
func auditDetails(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// getActorID extracts the user_id from fiber context or returns "system" if not present
func getActorID(c *fiber.Ctx) string {
	id := c.Get("X-Actor-ID")
	if id != "" {
		return id
	}
	id = c.Get("X-User-ID")
	if id != "" {
		return id
	}
	return ""
}

func (h *BillingAdminHandler) CreateAccount(c *fiber.Ctx) error {
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	account, err := h.AccountService.CreateAccount(input)
	if err != nil {
		logger.LogError("CreateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   getActorID(c),
			Action:    "create_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(account)
}

func (h *BillingAdminHandler) UpdateAccount(c *fiber.Ctx) error {
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	account, err := h.AccountService.UpdateAccount(input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   getActorID(c),
			Action:    "update_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(account)
}

func (h *BillingAdminHandler) GetAccount(c *fiber.Ctx) error {
	var input struct {
		ActorID string `json:"actor_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ActorID == "" {
		logger.LogError("GetAccount: actor_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "actor_id required"})
	}
	account, err := h.AccountService.GetAccount(input.ActorID)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        account.ID,
			ActorID:   input.ActorID,
			Action:    "get_account",
			TargetID:  account.ID,
			Details:   auditDetails(map[string]interface{}{"id": account.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(account)
}

func (h *BillingAdminHandler) ListAccounts(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListAccounts: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	accounts, err := h.AccountService.ListAccounts(input.TenantID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_accounts",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"accounts": accounts, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreatePlan(c *fiber.Ctx) error {
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	plan, err := h.PlanService.CreatePlan(input)
	if err != nil {
		logger.LogError("CreatePlan: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "create_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(plan)
}

func (h *BillingAdminHandler) UpdatePlan(c *fiber.Ctx) error {
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	plan, err := h.PlanService.UpdatePlan(input)
	if err != nil {
		logger.LogError("UpdatePlan: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "update_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(plan)
}

func (h *BillingAdminHandler) GetPlan(c *fiber.Ctx) error {
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PlanID == "" {
		logger.LogError("GetPlan: plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	plan, err := h.PlanService.GetPlan(input.PlanID)
	if err != nil {
		logger.LogError("GetPlan: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        plan.ID,
			ActorID:   getActorID(c),
			Action:    "get_plan",
			TargetID:  plan.ID,
			Details:   auditDetails(map[string]interface{}{"id": plan.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(plan)
}

func (h *BillingAdminHandler) ListPlans(c *fiber.Ctx) error {
	var input struct {
		ActiveOnly bool `json:"active_only"`
		Page       int  `json:"page"`
		PageSize   int  `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListPlans: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	plans, err := h.PlanService.ListPlans(input.ActiveOnly, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListPlans: failed", logger.ErrorField(err), logger.Bool("active_only", input.ActiveOnly))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_plans",
			TargetID:  "",
			Details:   auditDetails(map[string]interface{}{"active_only": input.ActiveOnly, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"plans": plans, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) DeletePlan(c *fiber.Ctx) error {
	var input struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PlanID == "" {
		logger.LogError("DeletePlan: plan_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.PlanService.DeletePlan(input.PlanID); err != nil {
		logger.LogError("DeletePlan: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.PlanID,
			ActorID:   getActorID(c),
			Action:    "delete_plan",
			TargetID:  input.PlanID,
			Details:   auditDetails(map[string]interface{}{"id": input.PlanID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateUsage(c *fiber.Ctx) error {
	var input Usage
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateUsage: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	usage, err := h.UsageService.CreateUsage(input)
	if err != nil {
		logger.LogError("CreateUsage: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        usage.ID,
			ActorID:   getActorID(c),
			Action:    "create_usage",
			TargetID:  usage.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(usage)
}

func (h *BillingAdminHandler) ListUsage(c *fiber.Ctx) error {
	var input struct {
		AccountID string `json:"account_id"`
		Metric    string `json:"metric"`
		Period    string `json:"period"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListUsage: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	usages, err := h.UsageService.ListUsage(input.AccountID, input.Metric, input.Period, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListUsage: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID), logger.String("metric", input.Metric), logger.String("period", input.Period))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_usage",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "metric": input.Metric, "period": input.Period, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"usages": usages, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateInvoice(c *fiber.Ctx) error {
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	invoice, err := h.InvoiceService.CreateInvoice(input)
	if err != nil {
		logger.LogError("CreateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(invoice)
}

func (h *BillingAdminHandler) UpdateInvoice(c *fiber.Ctx) error {
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	invoice, err := h.InvoiceService.UpdateInvoice(input)
	if err != nil {
		logger.LogError("UpdateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "update_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) GetInvoice(c *fiber.Ctx) error {
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		logger.LogError("GetInvoice: invoice_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	invoice, err := h.InvoiceService.GetInvoice(input.InvoiceID)
	if err != nil {
		logger.LogError("GetInvoice: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        invoice.ID,
			ActorID:   getActorID(c),
			Action:    "get_invoice",
			TargetID:  invoice.AccountID,
			Details:   auditDetails(map[string]interface{}{"id": invoice.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) ListInvoices(c *fiber.Ctx) error {
	var input struct {
		AccountID string `json:"account_id"`
		Status    string `json:"status"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListInvoices: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	invoices, err := h.InvoiceService.ListInvoices(input.AccountID, input.Status, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListInvoices: failed", logger.ErrorField(err), logger.String("account_id", input.AccountID), logger.String("status", input.Status))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_invoices",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "status": input.Status, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"invoices": invoices, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreatePayment(c *fiber.Ctx) error {
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	payment, err := h.PaymentService.CreatePayment(input)
	if err != nil {
		logger.LogError("CreatePayment: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "create_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(payment)
}

func (h *BillingAdminHandler) UpdatePayment(c *fiber.Ctx) error {
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	payment, err := h.PaymentService.UpdatePayment(input)
	if err != nil {
		logger.LogError("UpdatePayment: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "update_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(payment)
}

func (h *BillingAdminHandler) GetPayment(c *fiber.Ctx) error {
	var input struct {
		PaymentID string `json:"payment_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.PaymentID == "" {
		logger.LogError("GetPayment: payment_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "payment_id required"})
	}
	payment, err := h.PaymentService.GetPayment(input.PaymentID)
	if err != nil {
		logger.LogError("GetPayment: not found", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "payment method not found"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        payment.ID,
			ActorID:   getActorID(c),
			Action:    "get_payment",
			TargetID:  payment.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"id": payment.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(payment)
}

func (h *BillingAdminHandler) ListPayments(c *fiber.Ctx) error {
	var input struct {
		InvoiceID string `json:"invoice_id"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListPayments: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	payments, err := h.PaymentService.ListPayments(input.InvoiceID, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListPayments: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_payments",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"payments": payments, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateDiscount(c *fiber.Ctx) error {
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	discount, err := h.DiscountService.CreateDiscount(input)
	if err != nil {
		logger.LogError("CreateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "create_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(discount)
}

func (h *BillingAdminHandler) UpdateDiscount(c *fiber.Ctx) error {
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateDiscount: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	discount, err := h.DiscountService.UpdateDiscount(input)
	if err != nil {
		logger.LogError("UpdateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "update_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) DeleteDiscount(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteDiscount: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.DiscountService.DeleteDiscount(input.ID); err != nil {
		logger.LogError("DeleteDiscount: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_discount",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetDiscount(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetDiscount: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	discount, err := h.DiscountService.GetDiscount(input.ID)
	if err != nil {
		logger.LogError("GetDiscount: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "get_discount",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) GetDiscountByCode(c *fiber.Ctx) error {
	var input struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" {
		logger.LogError("GetDiscountByCode: code required", logger.String("code", input.Code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	discount, err := h.DiscountService.GetDiscountByCode(input.Code)
	if err != nil {
		logger.LogError("GetDiscountByCode: not found", logger.ErrorField(err), logger.String("code", input.Code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        discount.ID,
			ActorID:   getActorID(c),
			Action:    "get_discount_by_code",
			TargetID:  discount.ID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(discount)
}

func (h *BillingAdminHandler) ListDiscounts(c *fiber.Ctx) error {
	var input struct {
		ActiveOnly bool `json:"active_only"`
		Page       int  `json:"page"`
		PageSize   int  `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListDiscounts: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	discounts, err := h.DiscountService.ListDiscounts(input.ActiveOnly, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListDiscounts: failed", logger.ErrorField(err), logger.Bool("active_only", input.ActiveOnly))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_discounts",
			TargetID:  "",
			Details:   auditDetails(map[string]interface{}{"active_only": input.ActiveOnly, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"discounts": discounts, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateCoupon(c *fiber.Ctx) error {
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	coupon, err := h.CouponService.CreateCoupon(input)
	if err != nil {
		logger.LogError("CreateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "create_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(coupon)
}

func (h *BillingAdminHandler) UpdateCoupon(c *fiber.Ctx) error {
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateCoupon: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	coupon, err := h.CouponService.UpdateCoupon(input)
	if err != nil {
		logger.LogError("UpdateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "update_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) DeleteCoupon(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteCoupon: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CouponService.DeleteCoupon(input.ID); err != nil {
		logger.LogError("DeleteCoupon: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_coupon",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetCoupon(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetCoupon: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	coupon, err := h.CouponService.GetCoupon(input.ID)
	if err != nil {
		logger.LogError("GetCoupon: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "get_coupon",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) GetCouponByCode(c *fiber.Ctx) error {
	var input struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" {
		logger.LogError("GetCouponByCode: code required", logger.String("code", input.Code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	coupon, err := h.CouponService.GetCouponByCode(input.Code)
	if err != nil {
		logger.LogError("GetCouponByCode: not found", logger.ErrorField(err), logger.String("code", input.Code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "get_coupon_by_code",
			TargetID:  coupon.ID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ListCoupons(c *fiber.Ctx) error {
	var input struct {
		DiscountID string `json:"discount_id"`
		IsActive   *bool  `json:"is_active"`
		Page       int    `json:"page"`
		PageSize   int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListCoupons: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	coupons, err := h.CouponService.ListCoupons(input.DiscountID, input.IsActive, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListCoupons: failed", logger.ErrorField(err), logger.String("discount_id", input.DiscountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_coupons",
			TargetID:  input.DiscountID,
			Details:   auditDetails(map[string]interface{}{"discount_id": input.DiscountID, "is_active": input.IsActive, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"coupons": coupons, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateCredit(c *fiber.Ctx) error {
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	credit, err := h.CreditService.CreateCredit(input)
	if err != nil {
		logger.LogError("CreateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "create_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(credit)
}

func (h *BillingAdminHandler) UpdateCredit(c *fiber.Ctx) error {
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	credit, err := h.CreditService.UpdateCredit(input)
	if err != nil {
		logger.LogError("UpdateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "update_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(credit)
}

func (h *BillingAdminHandler) PatchCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	action := c.Query("action")
	amount := c.QueryFloat("amount", 0)
	if id == "" || action == "" {
		logger.LogError("PatchCredit: id and action required", logger.String("id", id), logger.String("action", action))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	if err := h.CreditService.PatchCredit(id, action, amount); err != nil {
		logger.LogError("PatchCredit: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "patch_credit",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"action": action, "amount": amount}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) DeleteCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCredit: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CreditService.DeleteCredit(id); err != nil {
		logger.LogError("DeleteCredit: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "delete_credit",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetCredit: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	credit, err := h.CreditService.GetCredit(id)
	if err != nil {
		logger.LogError("GetCredit: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        credit.ID,
			ActorID:   getActorID(c),
			Action:    "get_credit",
			TargetID:  credit.AccountID,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(credit)
}

func (h *BillingAdminHandler) ListCredits(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	credits, err := h.CreditService.ListCredits(accountID, invoiceID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListCredits: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("invoice_id", invoiceID), logger.String("status", status))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_credits",
			TargetID:  accountID,
			Details:   auditDetails(map[string]interface{}{"account_id": accountID, "invoice_id": invoiceID, "status": status, "page": page, "page_size": pageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"credits": credits, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreateRefund(c *fiber.Ctx) error {
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	refund, err := h.RefundService.CreateRefund(input)
	if err != nil {
		logger.LogError("CreateRefund: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "create_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) UpdateRefund(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateRefund: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.UpdateRefund(input.ID); err != nil {
		logger.LogError("UpdateRefund: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_refund",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteRefund(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteRefund: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.DeleteRefund(input.ID); err != nil {
		logger.LogError("DeleteRefund: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_refund",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetRefund: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	refund, err := h.RefundService.GetRefund(id)
	if err != nil {
		logger.LogError("GetRefund: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "get_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(refund)
}

func (h *BillingAdminHandler) ListRefunds(c *fiber.Ctx) error {
	paymentID := c.Query("payment_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	refunds, err := h.RefundService.ListRefunds(paymentID, invoiceID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListRefunds: failed", logger.ErrorField(err), logger.String("payment_id", paymentID), logger.String("invoice_id", invoiceID), logger.String("status", status))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_refunds",
			TargetID:  paymentID,
			Details:   auditDetails(map[string]interface{}{"payment_id": paymentID, "invoice_id": invoiceID, "status": status, "page": page, "page_size": pageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"refunds": refunds, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	var input struct {
		PaymentMethod PaymentMethod     `json:"payment_method"`
		PaymentData   map[string]string `json:"payment_data"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.PaymentMethod.Validate(); err != nil {
		logger.LogError("CreatePaymentMethod: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	pm, err := h.PaymentMethodService.CreatePaymentMethod(input.PaymentMethod, input.PaymentData)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create payment method"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "create_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(pm)
}

func (h *BillingAdminHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdatePaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePaymentMethod: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	pm, err := h.PaymentMethodService.UpdatePaymentMethod(input)
	if err != nil {
		logger.LogError("UpdatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update payment method"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "update_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(pm)
}

func (h *BillingAdminHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	var input struct {
		ID         string `json:"id"`
		SetDefault *bool  `json:"set_default"`
		Status     string `json:"status"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("PatchPaymentMethod: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.PatchPaymentMethod(input.ID, input.SetDefault, input.Status); err != nil {
		logger.LogError("PatchPaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update payment method"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "patch_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Status, "set_default": input.SetDefault}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	pm, err := h.PaymentMethodService.GetPaymentMethod(id)
	if err != nil {
		logger.LogError("GetPaymentMethod: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "payment method not found"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        pm.ID,
			ActorID:   getActorID(c),
			Action:    "get_payment_method",
			TargetID:  pm.ID,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(pm)
}

func (h *BillingAdminHandler) ListPaymentMethods(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	methods, err := h.PaymentMethodService.ListPaymentMethods(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListPaymentMethods: failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to list payment methods"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_payment_methods",
			TargetID:  accountID,
			Details:   auditDetails(map[string]interface{}{"account_id": accountID, "status": status, "page": page, "page_size": pageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"payment_methods": methods, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreateSubscription(c *fiber.Ctx) error {
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateSubscription: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := h.SubscriptionService.CreateSubscription(input)
	if err != nil {
		logger.LogError("CreateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "create_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(sub)
}

func (h *BillingAdminHandler) UpdateSubscription(c *fiber.Ctx) error {
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateSubscription: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := h.SubscriptionService.UpdateSubscription(input)
	if err != nil {
		logger.LogError("UpdateSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "update_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(sub)
}

func (h *BillingAdminHandler) PatchSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	action := c.Query("action")
	if id == "" || action == "" {
		logger.LogError("PatchSubscription: id and action required", logger.String("id", id), logger.String("action", action))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	if err := h.SubscriptionService.PatchSubscription(id, action); err != nil {
		logger.LogError("PatchSubscription: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "patch_subscription",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"action": action}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) DeleteSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.DeleteSubscription(id); err != nil {
		logger.LogError("DeleteSubscription: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to delete subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "delete_subscription",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	sub, err := h.SubscriptionService.GetSubscription(id)
	if err != nil {
		logger.LogError("GetSubscription: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "subscription not found"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        sub.ID,
			ActorID:   getActorID(c),
			Action:    "get_subscription",
			TargetID:  sub.ID,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(sub)
}

func (h *BillingAdminHandler) ListSubscriptions(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	subs, err := h.SubscriptionService.ListSubscriptions(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListSubscriptions: failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to list subscriptions"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_subscriptions",
			TargetID:  accountID,
			Details:   auditDetails(map[string]interface{}{"account_id": accountID, "status": status, "page": page, "page_size": pageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"subscriptions": subs, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) ChangePlanSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("ChangePlanSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var req struct {
		PlanID   string  `json:"plan_id"`
		ChangeAt *string `json:"change_at,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("ChangePlanSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.PlanID == "" {
		logger.LogError("ChangePlanSubscription: plan_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.SubscriptionService.ChangePlanSubscription(id, req.PlanID); err != nil {
		logger.LogError("ChangePlanSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to change plan"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "change_plan_subscription",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"plan_id": req.PlanID, "change_at": req.ChangeAt}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CancelSubscriptionNow(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("CancelSubscriptionNow: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.CancelSubscriptionNow(id); err != nil {
		logger.LogError("CancelSubscriptionNow: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to cancel subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "cancel_subscription_now",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) ResumeSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("ResumeSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.SubscriptionService.ResumeSubscription(id); err != nil {
		logger.LogError("ResumeSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to resume subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "resume_subscription",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"id": id}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) UpgradeNowSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpgradeNowSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("UpgradeNowSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.PlanID == "" {
		logger.LogError("UpgradeNowSubscription: plan_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.SubscriptionService.UpgradeNowSubscription(id); err != nil {
		logger.LogError("UpgradeNowSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to upgrade subscription"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        id,
			ActorID:   getActorID(c),
			Action:    "upgrade_now_subscription",
			TargetID:  id,
			Details:   auditDetails(map[string]interface{}{"plan_id": req.PlanID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateWebhookEvent(c *fiber.Ctx) error {
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateWebhookEvent: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	event, err := h.WebhookEventService.CreateWebhookEvent(input)
	if err != nil {
		logger.LogError("CreateWebhookEvent: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        event.ID,
			ActorID:   getActorID(c),
			Action:    "create_webhook_event",
			TargetID:  event.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(event)
}

func (h *BillingAdminHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookEventService.UpdateWebhookEvent(input.ID); err != nil {
		logger.LogError("UpdateWebhookEvent: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_webhook_event",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookEventService.DeleteWebhookEvent(input.ID); err != nil {
		logger.LogError("DeleteWebhookEvent: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_webhook_event",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetWebhookEvent(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetWebhookEvent: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	event, err := h.WebhookEventService.GetWebhookEvent(input.ID)
	if err != nil {
		logger.LogError("GetWebhookEvent: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        event.ID,
			ActorID:   getActorID(c),
			Action:    "get_webhook_event",
			TargetID:  event.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(event)
}

func (h *BillingAdminHandler) ListWebhookEvents(c *fiber.Ctx) error {
	var input struct {
		Provider string `json:"provider"`
		Status   string `json:"status"`
		Type     string `json:"type"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListWebhookEvents: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	events, err := h.WebhookEventService.ListWebhookEvents(input.Provider, input.Status, input.Type, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListWebhookEvents: failed", logger.ErrorField(err), logger.String("provider", input.Provider))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_webhook_events",
			TargetID:  input.Provider,
			Details:   auditDetails(map[string]interface{}{"provider": input.Provider, "status": input.Status, "type": input.Type, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"webhook_events": events, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateInvoiceAdjustment(c *fiber.Ctx) error {
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	adj, err := h.InvoiceAdjustmentService.CreateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("CreateInvoiceAdjustment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("UpdateInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.InvoiceAdjustmentService.UpdateInvoiceAdjustment(input.ID); err != nil {
		logger.LogError("UpdateInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "update_invoice_adjustment",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeleteInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.InvoiceAdjustmentService.DeleteInvoiceAdjustment(input.ID); err != nil {
		logger.LogError("DeleteInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_invoice_adjustment",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoiceAdjustment: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	adj, err := h.InvoiceAdjustmentService.GetInvoiceAdjustment(input.ID)
	if err != nil {
		logger.LogError("GetInvoiceAdjustment: not found", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "get_invoice_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(adj)
}

func (h *BillingAdminHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	var input struct {
		InvoiceID string `json:"invoice_id"`
		Type      string `json:"type"`
		Page      int    `json:"page"`
		PageSize  int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("ListInvoiceAdjustments: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	adjs, err := h.InvoiceAdjustmentService.ListInvoiceAdjustments(input.InvoiceID, input.Type, input.Page, input.PageSize)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_invoice_adjustments",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID, "type": input.Type, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingAdminHandler) CreateManualAdjustment(c *fiber.Ctx) error {
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	adj, err := h.ManualAdjustmentService.CreateManualAdjustment(input)
	if err != nil {
		logger.LogError("CreateManualAdjustment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        adj.ID,
			ActorID:   getActorID(c),
			Action:    "create_manual_adjustment",
			TargetID:  adj.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) CreateManualRefund(c *fiber.Ctx) error {
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	refund, err := h.ManualRefundService.CreateManualRefund(input)
	if err != nil {
		logger.LogError("CreateManualRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        refund.ID,
			ActorID:   getActorID(c),
			Action:    "create_manual_refund",
			TargetID:  refund.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) PerformAccountAction(c *fiber.Ctx) error {
	var input struct {
		ID     string                 `json:"id"`
		Action string                 `json:"action"`
		Params map[string]interface{} `json:"params"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" || input.Action == "" {
		logger.LogError("PerformAccountAction: id and action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id and action required"})
	}
	result, err := h.AccountActionService.PerformAccountAction(c.Context(), input.ID, input.Action, input.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", input.ID), logger.String("action", input.Action))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "perform_account_action",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"action": input.Action, "params": input.Params}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *BillingAdminHandler) GetInvoicePreview(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoicePreview: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to delete payment method"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) RedeemCoupon(c *fiber.Ctx) error {
	var input struct {
		Code      string `json:"code"`
		AccountID string `json:"account_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.Code == "" || input.AccountID == "" {
		logger.LogError("RedeemCoupon: code and account_id required", logger.String("code", input.Code), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code and account_id required"})
	}
	coupon, err := h.CouponService.RedeemCoupon(input.Code, input.AccountID)
	if err != nil {
		logger.LogError("RedeemCoupon: failed", logger.ErrorField(err), logger.String("code", input.Code))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        coupon.ID,
			ActorID:   getActorID(c),
			Action:    "redeem_coupon",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"code": input.Code, "account_id": input.AccountID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required", logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(input.InvoiceID); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.InvoiceID,
			ActorID:   getActorID(c),
			Action:    "apply_credits_to_invoice",
			TargetID:  input.InvoiceID,
			Details:   auditDetails(map[string]interface{}{"invoice_id": input.InvoiceID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	var input struct{}
	_ = c.BodyParser(&input) // Accepts empty body for consistency
	cfg, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "billing_config",
			ActorID:   getActorID(c),
			Action:    "get_billing_config",
			TargetID:  "billing_config",
			Details:   auditDetails(cfg),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(cfg)
}

func (h *BillingAdminHandler) SetBillingConfig(c *fiber.Ctx) error {
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetBillingConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.InvoiceService.SetBillingConfig(input); err != nil {
		logger.LogError("SetBillingConfig: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "billing_config",
			ActorID:   getActorID(c),
			Action:    "set_billing_config",
			TargetID:  "billing_config",
			Details:   auditDetails(input),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateWebhookSubscription(c *fiber.Ctx) error {
	var input WebhookSubscription
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.WebhookSubscriptionService.CreateWebhookSubscription(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "create_webhook_subscription",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) ListWebhookSubscriptions(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
		Page     int    `json:"page"`
		PageSize int    `json:"page_size"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 100
	}
	out, err := h.WebhookSubscriptionService.ListWebhookSubscriptions(c.Context(), input.TenantID, input.Page, input.PageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "",
			ActorID:   getActorID(c),
			Action:    "list_webhook_subscriptions",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID, "page": input.Page, "page_size": input.PageSize}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) DeleteWebhookSubscription(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookSubscriptionService.DeleteWebhookSubscription(c.Context(), input.ID); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_webhook_subscription",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"subscription_id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) SetTaxInfo(c *fiber.Ctx) error {
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "set_tax_info",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) GetTaxInfo(c *fiber.Ctx) error {
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.GetTaxInfo(c.Context(), input.TenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.TenantID,
			ActorID:   getActorID(c),
			Action:    "get_tax_info",
			TargetID:  input.TenantID,
			Details:   auditDetails(map[string]interface{}{"tenant_id": input.TenantID}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetRevenueReport(c *fiber.Ctx) error {
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetRevenueReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "revenue_report",
			ActorID:   getActorID(c),
			Action:    "get_revenue_report",
			TargetID:  "revenue_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetARReport(c *fiber.Ctx) error {
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetARReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "ar_report",
			ActorID:   getActorID(c),
			Action:    "get_ar_report",
			TargetID:  "ar_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetChurnReport(c *fiber.Ctx) error {
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetChurnReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "churn_report",
			ActorID:   getActorID(c),
			Action:    "get_churn_report",
			TargetID:  "churn_report",
			Details:   auditDetails(out),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) AggregateUsageForBillingCycle(c *fiber.Ctx) error {
	var input struct {
		AccountID   string `json:"account_id"`
		PeriodStart string `json:"period_start"`
		PeriodEnd   string `json:"period_end"`
	}
	if err := c.BodyParser(&input); err != nil || input.AccountID == "" || input.PeriodStart == "" || input.PeriodEnd == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id, period_start, and period_end required"})
	}
	periodStart, err := time.Parse(time.RFC3339, input.PeriodStart)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_start format"})
	}
	periodEnd, err := time.Parse(time.RFC3339, input.PeriodEnd)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_end format"})
	}
	out, err := h.Store.AggregateUsageForBillingCycle(c.Context(), input.AccountID, periodStart, periodEnd)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "aggregate_usage",
			ActorID:   getActorID(c),
			Action:    "aggregate_usage_for_billing_cycle",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "period_start": input.PeriodStart, "period_end": input.PeriodEnd}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CalculateOverageCharges(c *fiber.Ctx) error {
	var input struct {
		AccountID   string `json:"account_id"`
		PlanID      string `json:"plan_id"`
		PeriodStart string `json:"period_start"`
		PeriodEnd   string `json:"period_end"`
	}
	if err := c.BodyParser(&input); err != nil || input.AccountID == "" || input.PlanID == "" || input.PeriodStart == "" || input.PeriodEnd == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id, plan_id, period_start, and period_end required"})
	}
	periodStart, err := time.Parse(time.RFC3339, input.PeriodStart)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_start format"})
	}
	periodEnd, err := time.Parse(time.RFC3339, input.PeriodEnd)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid period_end format"})
	}
	out, err := h.Store.CalculateOverageCharges(c.Context(), input.AccountID, input.PlanID, periodStart, periodEnd)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        "overage_charges",
			ActorID:   getActorID(c),
			Action:    "calculate_overage_charges",
			TargetID:  input.AccountID,
			Details:   auditDetails(map[string]interface{}{"account_id": input.AccountID, "plan_id": input.PlanID, "period_start": input.PeriodStart, "period_end": input.PeriodEnd}),
			CreatedAt: time.Now(),
		})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CreateInvoiceWithFeesAndTax(c *fiber.Ctx) error {
	var input struct {
		Invoice    Invoice `json:"invoice"`
		FixedFee   float64 `json:"fixed_fee"`
		PercentFee float64 `json:"percent_fee"`
		TaxRate    float64 `json:"tax_rate"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.Store.CreateInvoiceWithFeesAndTax(c.Context(), input.Invoice, input.FixedFee, input.PercentFee, input.TaxRate)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        out.ID,
			ActorID:   getActorID(c),
			Action:    "create_invoice_with_fees_and_tax",
			TargetID:  out.ID,
			Details:   auditDetails(map[string]interface{}{"input": input}),
			CreatedAt: time.Now(),
		})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("DeletePaymentMethod: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to delete payment method"})
	}
	if h.AuditLogger != nil {
		go h.AuditLogger.CreateSecurityAuditLog(c.Context(), security_management.SecurityAuditLog{
			ID:        input.ID,
			ActorID:   getActorID(c),
			Action:    "delete_payment_method",
			TargetID:  input.ID,
			Details:   auditDetails(map[string]interface{}{"id": input.ID}),
			CreatedAt: time.Now(),
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
