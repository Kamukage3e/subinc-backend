package billing_management

import (
	"context"
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
	APIUsageService            APIUsageService
	APIKeyService              APIKeyService
	RateLimitService           RateLimitService
	SLAService                 SLAService
	PluginService              PluginService
	WebhookSubscriptionService WebhookSubscriptionService
	TaxInfoService             TaxInfoService
	Store                      *PostgresStore
	AuditLogger                security_management.AuditLogger
	// Add all other real service dependencies here as you migrate
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
	actor, ok := c.Locals("user_id").(string)
	if ok && actor != "" {
		return actor
	}
	return "system"
}

func (h *BillingAdminHandler) logAudit(ctx context.Context, log AuditLog) {
	if h.AuditLogger == nil {
		h.AuditLogger = security_management.NoopAuditLogger{}
	}
	// Details is always a string now
	detailsStr := log.Details
	_, err := h.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
		ID:        log.ID,
		ActorID:   log.ActorID,
		Action:    log.Action,
		TargetID:  log.TargetID,
		Details:   detailsStr,
		CreatedAt: log.CreatedAt,
	})
	if err != nil {
		logger.LogError("audit log write failed", logger.ErrorField(err), logger.Any("audit_log", log))
	}
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        account.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_account",
		TargetID:  account.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(account)
}

func (h *BillingAdminHandler) UpdateAccount(c *fiber.Ctx) error {
	var input Account
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateAccount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	account, err := h.AccountService.UpdateAccount(input)
	if err != nil {
		logger.LogError("UpdateAccount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        account.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_account",
		TargetID:  account.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(account)
}

func (h *BillingAdminHandler) GetAccount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetAccount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	account, err := h.AccountService.GetAccount(id)
	if err != nil {
		logger.LogError("GetAccount: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        account.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_account",
		TargetID:  account.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(account)
}

func (h *BillingAdminHandler) ListAccounts(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	accounts, err := h.AccountService.ListAccounts(tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListAccounts: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_accounts",
		TargetID:  tenantID,
		Details:   auditDetails(map[string]interface{}{"tenant_id": tenantID, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"accounts": accounts, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        plan.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_plan",
		TargetID:  plan.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(plan)
}

func (h *BillingAdminHandler) UpdatePlan(c *fiber.Ctx) error {
	var input Plan
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePlan: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	plan, err := h.PlanService.UpdatePlan(input)
	if err != nil {
		logger.LogError("UpdatePlan: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        plan.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_plan",
		TargetID:  plan.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(plan)
}

func (h *BillingAdminHandler) GetPlan(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPlan: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	plan, err := h.PlanService.GetPlan(id)
	if err != nil {
		logger.LogError("GetPlan: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        plan.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_plan",
		TargetID:  plan.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(plan)
}

func (h *BillingAdminHandler) ListPlans(c *fiber.Ctx) error {
	activeOnly := c.QueryBool("active_only", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	plans, err := h.PlanService.ListPlans(activeOnly, page, pageSize)
	if err != nil {
		logger.LogError("ListPlans: failed", logger.ErrorField(err), logger.Bool("active_only", activeOnly))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_plans",
		TargetID:  "",
		Details:   auditDetails(map[string]interface{}{"active_only": activeOnly, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"plans": plans, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) DeletePlan(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeletePlan: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PlanService.DeletePlan(id); err != nil {
		logger.LogError("DeletePlan: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   c.Locals("user_id").(string),
		Action:    "delete_plan",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        usage.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_usage",
		TargetID:  usage.AccountID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(usage)
}

func (h *BillingAdminHandler) ListUsage(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	metric := c.Query("metric")
	period := c.Query("period")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	usages, err := h.UsageService.ListUsage(accountID, metric, period, page, pageSize)
	if err != nil {
		logger.LogError("ListUsage: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("metric", metric), logger.String("period", period))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_usage",
		TargetID:  accountID,
		Details:   auditDetails(map[string]interface{}{"account_id": accountID, "metric": metric, "period": period, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"usages": usages, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        invoice.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_invoice",
		TargetID:  invoice.AccountID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(invoice)
}

func (h *BillingAdminHandler) UpdateInvoice(c *fiber.Ctx) error {
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	invoice, err := h.InvoiceService.UpdateInvoice(input)
	if err != nil {
		logger.LogError("UpdateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        invoice.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_invoice",
		TargetID:  invoice.AccountID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) GetInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetInvoice: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	invoice, err := h.InvoiceService.GetInvoice(id)
	if err != nil {
		logger.LogError("GetInvoice: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        invoice.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_invoice",
		TargetID:  invoice.AccountID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) ListInvoices(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	invoices, err := h.InvoiceService.ListInvoices(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListInvoices: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("status", status))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_invoices",
		TargetID:  accountID,
		Details:   auditDetails(map[string]interface{}{"account_id": accountID, "status": status, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"invoices": invoices, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        payment.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_payment",
		TargetID:  payment.InvoiceID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(payment)
}

func (h *BillingAdminHandler) UpdatePayment(c *fiber.Ctx) error {
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	payment, err := h.PaymentService.UpdatePayment(input)
	if err != nil {
		logger.LogError("UpdatePayment: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        payment.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_payment",
		TargetID:  payment.InvoiceID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(payment)
}

func (h *BillingAdminHandler) GetPayment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPayment: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	payment, err := h.PaymentService.GetPayment(id)
	if err != nil {
		logger.LogError("GetPayment: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        payment.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_payment",
		TargetID:  payment.InvoiceID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(payment)
}

func (h *BillingAdminHandler) ListPayments(c *fiber.Ctx) error {
	invoiceID := c.Query("invoice_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	payments, err := h.PaymentService.ListPayments(invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("ListPayments: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_payments",
		TargetID:  invoiceID,
		Details:   auditDetails(map[string]interface{}{"invoice_id": invoiceID, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"payments": payments, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        discount.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_discount",
		TargetID:  discount.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(discount)
}

func (h *BillingAdminHandler) UpdateDiscount(c *fiber.Ctx) error {
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	discount, err := h.DiscountService.UpdateDiscount(input)
	if err != nil {
		logger.LogError("UpdateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        discount.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_discount",
		TargetID:  discount.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(discount)
}

func (h *BillingAdminHandler) DeleteDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteDiscount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.DiscountService.DeleteDiscount(id); err != nil {
		logger.LogError("DeleteDiscount: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   c.Locals("user_id").(string),
		Action:    "delete_discount",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetDiscount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	discount, err := h.DiscountService.GetDiscount(id)
	if err != nil {
		logger.LogError("GetDiscount: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        discount.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_discount",
		TargetID:  discount.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(discount)
}

func (h *BillingAdminHandler) GetDiscountByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		logger.LogError("GetDiscountByCode: code required", logger.String("code", code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	discount, err := h.DiscountService.GetDiscountByCode(code)
	if err != nil {
		logger.LogError("GetDiscountByCode: not found", logger.ErrorField(err), logger.String("code", code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        discount.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_discount_by_code",
		TargetID:  discount.ID,
		Details:   auditDetails(map[string]interface{}{"code": code}),
		CreatedAt: time.Now(),
	})
	return c.JSON(discount)
}

func (h *BillingAdminHandler) ListDiscounts(c *fiber.Ctx) error {
	activeOnly := c.QueryBool("active_only", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	discounts, err := h.DiscountService.ListDiscounts(activeOnly, page, pageSize)
	if err != nil {
		logger.LogError("ListDiscounts: failed", logger.ErrorField(err), logger.Bool("active_only", activeOnly))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_discounts",
		TargetID:  "",
		Details:   auditDetails(map[string]interface{}{"active_only": activeOnly, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"discounts": discounts, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        coupon.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_coupon",
		TargetID:  coupon.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(coupon)
}

func (h *BillingAdminHandler) UpdateCoupon(c *fiber.Ctx) error {
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
	coupon, err := h.CouponService.UpdateCoupon(input)
	if err != nil {
		logger.LogError("UpdateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        coupon.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_coupon",
		TargetID:  coupon.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) DeleteCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCoupon: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CouponService.DeleteCoupon(id); err != nil {
		logger.LogError("DeleteCoupon: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   c.Locals("user_id").(string),
		Action:    "delete_coupon",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetCoupon: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	coupon, err := h.CouponService.GetCoupon(id)
	if err != nil {
		logger.LogError("GetCoupon: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        coupon.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_coupon",
		TargetID:  coupon.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) GetCouponByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		logger.LogError("GetCouponByCode: code required", logger.String("code", code))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code required"})
	}
	coupon, err := h.CouponService.GetCouponByCode(code)
	if err != nil {
		logger.LogError("GetCouponByCode: not found", logger.ErrorField(err), logger.String("code", code))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        coupon.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_coupon_by_code",
		TargetID:  coupon.ID,
		Details:   auditDetails(map[string]interface{}{"code": code}),
		CreatedAt: time.Now(),
	})
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ListCoupons(c *fiber.Ctx) error {
	discountID := c.Query("discount_id")
	var isActive *bool
	if c.Query("is_active") != "" {
		b := c.QueryBool("is_active", false)
		isActive = &b
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	coupons, err := h.CouponService.ListCoupons(discountID, isActive, page, pageSize)
	if err != nil {
		logger.LogError("ListCoupons: failed", logger.ErrorField(err), logger.String("discount_id", discountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   c.Locals("user_id").(string),
		Action:    "list_coupons",
		TargetID:  discountID,
		Details:   auditDetails(map[string]interface{}{"discount_id": discountID, "is_active": isActive, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"coupons": coupons, "page": page, "page_size": pageSize})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        credit.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "create_credit",
		TargetID:  credit.AccountID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        credit.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "update_credit",
		TargetID:  credit.AccountID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   c.Locals("user_id").(string),
		Action:    "patch_credit",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"action": action, "amount": amount}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   c.Locals("user_id").(string),
		Action:    "delete_credit",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        credit.ID,
		ActorID:   c.Locals("user_id").(string),
		Action:    "get_credit",
		TargetID:  credit.AccountID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        refund.ID,
		ActorID:   getActorID(c),
		Action:    "create_refund",
		TargetID:  refund.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) UpdateRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateRefund: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.UpdateRefund(id); err != nil {
		logger.LogError("UpdateRefund: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   getActorID(c),
		Action:    "update_refund",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteRefund: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.RefundService.DeleteRefund(id); err != nil {
		logger.LogError("DeleteRefund: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   getActorID(c),
		Action:    "delete_refund",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        refund.ID,
		ActorID:   getActorID(c),
		Action:    "get_refund",
		TargetID:  refund.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   getActorID(c),
		Action:    "list_refunds",
		TargetID:  paymentID,
		Details:   auditDetails(map[string]interface{}{"payment_id": paymentID, "invoice_id": invoiceID, "status": status, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
	return c.JSON(fiber.Map{"refunds": refunds, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePaymentMethod: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	var paymentData map[string]string
	if err := c.BodyParser(&paymentData); err != nil {
		logger.LogError("CreatePaymentMethod: payment data parse failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payment data"})
	}
	pm, err := h.PaymentMethodService.CreatePaymentMethod(input, paymentData)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to create payment method"})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        pm.ID,
		ActorID:   getActorID(c),
		Action:    "create_payment_method",
		TargetID:  pm.ID,
		Details:   auditDetails(map[string]interface{}{"input": input, "payment_data": paymentData}),
		CreatedAt: time.Now(),
	})
	return c.Status(fiber.StatusCreated).JSON(pm)
}

func (h *BillingAdminHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        pm.ID,
		ActorID:   getActorID(c),
		Action:    "update_payment_method",
		TargetID:  pm.ID,
		Details:   auditDetails(map[string]interface{}{"input": input}),
		CreatedAt: time.Now(),
	})
	return c.JSON(pm)
}

func (h *BillingAdminHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	setDefault := c.QueryBool("set_default", false)
	status := c.Query("status")
	if id == "" {
		logger.LogError("PatchPaymentMethod: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.PatchPaymentMethod(id, &setDefault, status); err != nil {
		logger.LogError("PatchPaymentMethod: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   getActorID(c),
		Action:    "patch_payment_method",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"set_default": setDefault, "status": status}),
		CreatedAt: time.Now(),
	})
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeletePaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(id); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to delete payment method"})
	}
	go h.logAudit(c.Context(), AuditLog{
		ID:        id,
		ActorID:   getActorID(c),
		Action:    "delete_payment_method",
		TargetID:  id,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        pm.ID,
		ActorID:   getActorID(c),
		Action:    "get_payment_method",
		TargetID:  pm.ID,
		Details:   auditDetails(map[string]interface{}{"id": id}),
		CreatedAt: time.Now(),
	})
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
	go h.logAudit(c.Context(), AuditLog{
		ID:        "",
		ActorID:   getActorID(c),
		Action:    "list_payment_methods",
		TargetID:  accountID,
		Details:   auditDetails(map[string]interface{}{"account_id": accountID, "status": status, "page": page, "page_size": pageSize}),
		CreatedAt: time.Now(),
	})
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
	return c.Status(fiber.StatusCreated).JSON(sub)
}

func (h *BillingAdminHandler) UpdateSubscription(c *fiber.Ctx) error {
	var input Subscription
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = c.Params("id")
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
	return c.Status(fiber.StatusCreated).JSON(event)
}

func (h *BillingAdminHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.WebhookEventService.UpdateWebhookEvent(id); err != nil {
		logger.LogError("UpdateWebhookEvent: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.WebhookEventService.DeleteWebhookEvent(id); err != nil {
		logger.LogError("DeleteWebhookEvent: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	event, err := h.WebhookEventService.GetWebhookEvent(id)
	if err != nil {
		logger.LogError("GetWebhookEvent: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(event)
}

func (h *BillingAdminHandler) ListWebhookEvents(c *fiber.Ctx) error {
	provider := c.Query("provider")
	status := c.Query("status")
	eventType := c.Query("type")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	events, err := h.WebhookEventService.ListWebhookEvents(provider, status, eventType, page, pageSize)
	if err != nil {
		logger.LogError("ListWebhookEvents: failed", logger.ErrorField(err), logger.String("provider", provider))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"webhook_events": events, "page": page, "page_size": pageSize})
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
	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.InvoiceAdjustmentService.UpdateInvoiceAdjustment(id); err != nil {
		logger.LogError("UpdateInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusOK)
}

func (h *BillingAdminHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.InvoiceAdjustmentService.DeleteInvoiceAdjustment(id); err != nil {
		logger.LogError("DeleteInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	adj, err := h.InvoiceAdjustmentService.GetInvoiceAdjustment(id)
	if err != nil {
		logger.LogError("GetInvoiceAdjustment: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(adj)
}

func (h *BillingAdminHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	invoiceID := c.Query("invoice_id")
	typeParam := c.Query("type")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	adjs, err := h.InvoiceAdjustmentService.ListInvoiceAdjustments(invoiceID, typeParam, page, pageSize)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "page": page, "page_size": pageSize})
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
	return c.Status(fiber.StatusCreated).JSON(refund)
}

func (h *BillingAdminHandler) PerformAccountAction(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		logger.LogError("PerformAccountAction: account_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id required"})
	}
	var req struct {
		Action string                 `json:"action"`
		Params map[string]interface{} `json:"params"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("PerformAccountAction: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Action == "" {
		logger.LogError("PerformAccountAction: action required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action required"})
	}
	result, err := h.AccountActionService.PerformAccountAction(accountID, req.Action, req.Params)
	if err != nil {
		logger.LogError("PerformAccountAction: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", req.Action))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *BillingAdminHandler) GetInvoicePreview(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		logger.LogError("GetInvoicePreview: account_id required", logger.String("account_id", accountID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id required"})
	}
	invoice, err := h.InvoiceService.GetInvoicePreview(accountID)
	if err != nil {
		logger.LogError("GetInvoicePreview: failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) RedeemCoupon(c *fiber.Ctx) error {
	code := c.Params("code")
	accountID := c.Query("account_id")
	if code == "" || accountID == "" {
		logger.LogError("RedeemCoupon: code and account_id required", logger.String("code", code), logger.String("account_id", accountID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code and account_id required"})
	}
	coupon, err := h.CouponService.RedeemCoupon(code, accountID)
	if err != nil {
		logger.LogError("RedeemCoupon: failed", logger.ErrorField(err), logger.String("code", code))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	invoiceID := c.Params("id")
	if invoiceID == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required", logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(invoiceID); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	cfg, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	return c.SendStatus(fiber.StatusNoContent)
}

// APIUsage Handlers
func (h *BillingAdminHandler) CreateAPIUsage(c *fiber.Ctx) error {
	var input APIUsage
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.APIUsageService.CreateAPIUsage(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) ListAPIUsage(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	apiKeyID := c.Query("api_key_id")
	endpoint := c.Query("endpoint")
	periodStart, _ := time.Parse(time.RFC3339, c.Query("period_start"))
	periodEnd, _ := time.Parse(time.RFC3339, c.Query("period_end"))
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	out, err := h.APIUsageService.ListAPIUsage(c.Context(), tenantID, apiKeyID, endpoint, periodStart, periodEnd, page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

// APIKey Handlers
func (h *BillingAdminHandler) CreateAPIKey(c *fiber.Ctx) error {
	var input APIKey
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.APIKeyService.CreateAPIKey(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) RotateAPIKey(c *fiber.Ctx) error {
	apiKeyID := c.Params("id")
	actorID := c.Locals("actor_id").(string)
	out, err := h.APIKeyService.RotateAPIKey(c.Context(), apiKeyID, actorID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) RevokeAPIKey(c *fiber.Ctx) error {
	apiKeyID := c.Params("id")
	if err := h.APIKeyService.RevokeAPIKey(c.Context(), apiKeyID); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) ListAPIKeys(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	out, err := h.APIKeyService.ListAPIKeys(c.Context(), tenantID, page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

// RateLimit Handlers
func (h *BillingAdminHandler) SetRateLimit(c *fiber.Ctx) error {
	var input RateLimit
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.RateLimitService.SetRateLimit(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) GetRateLimit(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	apiKeyID := c.Query("api_key_id")
	out, err := h.RateLimitService.GetRateLimit(c.Context(), tenantID, apiKeyID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

// SLA Handlers
func (h *BillingAdminHandler) SetSLA(c *fiber.Ctx) error {
	var input SLA
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.SLAService.SetSLA(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) GetSLA(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	out, err := h.SLAService.GetSLA(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

// Plugin Handlers
func (h *BillingAdminHandler) RegisterPlugin(c *fiber.Ctx) error {
	var input Plugin
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.PluginService.RegisterPlugin(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) ListPlugins(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	out, err := h.PluginService.ListPlugins(c.Context(), tenantID, page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) UpdatePlugin(c *fiber.Ctx) error {
	var input Plugin
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.PluginService.UpdatePlugin(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) DeletePlugin(c *fiber.Ctx) error {
	pluginID := c.Params("id")
	if err := h.PluginService.DeletePlugin(c.Context(), pluginID); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// WebhookSubscription Handlers
func (h *BillingAdminHandler) CreateWebhookSubscription(c *fiber.Ctx) error {
	var input WebhookSubscription
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.WebhookSubscriptionService.CreateWebhookSubscription(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) ListWebhookSubscriptions(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	out, err := h.WebhookSubscriptionService.ListWebhookSubscriptions(c.Context(), tenantID, page, pageSize)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) DeleteWebhookSubscription(c *fiber.Ctx) error {
	subID := c.Params("id")
	if err := h.WebhookSubscriptionService.DeleteWebhookSubscription(c.Context(), subID); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// TaxInfo Handlers
func (h *BillingAdminHandler) SetTaxInfo(c *fiber.Ctx) error {
	var input TaxInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.TaxInfoService.SetTaxInfo(c.Context(), input)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *BillingAdminHandler) GetTaxInfo(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	out, err := h.TaxInfoService.GetTaxInfo(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetRevenueReport(c *fiber.Ctx) error {
	out, err := h.Store.GetRevenueReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetARReport(c *fiber.Ctx) error {
	out, err := h.Store.GetARReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) GetChurnReport(c *fiber.Ctx) error {
	out, err := h.Store.GetChurnReport(c.Context())
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) AggregateUsageForBillingCycle(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	periodStart, _ := time.Parse(time.RFC3339, c.Query("period_start"))
	periodEnd, _ := time.Parse(time.RFC3339, c.Query("period_end"))
	out, err := h.Store.AggregateUsageForBillingCycle(c.Context(), accountID, periodStart, periodEnd)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CalculateOverageCharges(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	planID := c.Query("plan_id")
	periodStart, _ := time.Parse(time.RFC3339, c.Query("period_start"))
	periodEnd, _ := time.Parse(time.RFC3339, c.Query("period_end"))
	out, err := h.Store.CalculateOverageCharges(c.Context(), accountID, planID, periodStart, periodEnd)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) CreateInvoiceWithFeesAndTax(c *fiber.Ctx) error {
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	fixedFee := c.QueryFloat("fixed_fee", 0)
	percentFee := c.QueryFloat("percent_fee", 0)
	taxRate := c.QueryFloat("tax_rate", 0)
	out, err := h.Store.CreateInvoiceWithFeesAndTax(c.Context(), input, fixedFee, percentFee, taxRate)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}
