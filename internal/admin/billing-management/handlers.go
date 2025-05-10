package billing_management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type BillingAdminHandler struct {
	AccountService           AccountService
	PlanService              PlanService
	UsageService             UsageService
	InvoiceService           InvoiceService
	PaymentService           PaymentService
	AuditLogService          AuditLogService
	DiscountService          DiscountService
	CouponService            CouponService
	CreditService            CreditService
	RefundService            RefundService
	PaymentMethodService     PaymentMethodService
	SubscriptionService      SubscriptionService
	WebhookEventService      WebhookEventService
	InvoiceAdjustmentService InvoiceAdjustmentService
	ManualAdjustmentService  ManualAdjustmentService
	ManualRefundService      ManualRefundService
	AccountActionService     AccountActionService
	// Add all other real service dependencies here as you migrate
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
	return c.JSON(fiber.Map{"payments": payments, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) ListAuditLogs(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	action := c.Query("action")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.AuditLogService.ListAuditLogs(accountID, action, page, pageSize)
	if err != nil {
		logger.LogError("ListAuditLogs: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) SearchAuditLogs(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	action := c.Query("action")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	logs, err := h.AuditLogService.SearchAuditLogs(accountID, action, startTime, endTime, page, pageSize)
	if err != nil {
		logger.LogError("SearchAuditLogs: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action), logger.String("start_time", startTime), logger.String("end_time", endTime))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreateAuditLog(c *fiber.Ctx) error {
	var input AuditLog
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateAuditLog: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	log, err := h.AuditLogService.CreateAuditLog(input)
	if err != nil {
		logger.LogError("CreateAuditLog: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(log)
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
	return c.JSON(credit)
}

func (h *BillingAdminHandler) PatchCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		Action string  `json:"action"`
		Amount float64 `json:"amount,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("PatchCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.CreditService.PatchCredit(id, req.Action, req.Amount); err != nil {
		logger.LogError("PatchCredit: failed", logger.ErrorField(err), logger.String("id", id), logger.String("action", req.Action))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
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
	return c.JSON(pm)
}

func (h *BillingAdminHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("PatchPaymentMethod: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var req struct {
		SetDefault *bool  `json:"set_default,omitempty"`
		Status     string `json:"status,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("PatchPaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.SetDefault != nil && *req.SetDefault {
		if err := h.PaymentMethodService.PatchPaymentMethod(id, req.SetDefault, ""); err != nil {
			logger.LogError("PatchPaymentMethod: set default failed", logger.ErrorField(err))
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to set default payment method"})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	if req.Status != "" {
		if err := h.PaymentMethodService.PatchPaymentMethod(id, nil, req.Status); err != nil {
			logger.LogError("PatchPaymentMethod: status update failed", logger.ErrorField(err))
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update payment method status"})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	logger.LogError("PatchPaymentMethod: no valid patch operation")
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "no valid patch operation"})
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
	if id == "" {
		logger.LogError("PatchSubscription: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var req struct {
		Status          string  `json:"status,omitempty"`
		ScheduledPlanID string  `json:"scheduled_plan_id,omitempty"`
		ChangeAt        *string `json:"change_at,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		logger.LogError("PatchSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Status != "" {
		err := h.SubscriptionService.PatchSubscription(id, "status:"+req.Status)
		if err != nil {
			logger.LogError("PatchSubscription: status update failed", logger.ErrorField(err))
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to update subscription status"})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	if req.ScheduledPlanID != "" && req.ChangeAt != nil {
		err := h.SubscriptionService.PatchSubscription(id, "plan:"+req.ScheduledPlanID+":"+*req.ChangeAt)
		if err != nil {
			logger.LogError("PatchSubscription: plan change failed", logger.ErrorField(err))
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to schedule plan change"})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
	logger.LogError("PatchSubscription: no valid patch operation")
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "no valid patch operation"})
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
	accountID := c.Query("account_id")
	if accountID == "" {
		logger.LogError("GetInvoicePreview: account_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id required"})
	}
	preview, err := h.InvoiceService.GetInvoicePreview(accountID)
	if err != nil {
		logger.LogError("GetInvoicePreview: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to get invoice preview"})
	}
	return c.JSON(preview)
}

func (h *BillingAdminHandler) RedeemCoupon(c *fiber.Ctx) error {
	code := c.Params("code")
	accountID := c.Query("account_id")
	if code == "" || accountID == "" {
		logger.LogError("RedeemCoupon: code and account_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code and account_id required"})
	}
	coupon, err := h.CouponService.RedeemCoupon(code, accountID)
	if err != nil {
		logger.LogError("RedeemCoupon: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to redeem coupon"})
	}
	return c.JSON(coupon)
}

func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	invoiceID := c.Params("id")
	if invoiceID == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(invoiceID); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to apply credits"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	config, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to get billing config"})
	}
	return c.JSON(config)
}

func (h *BillingAdminHandler) SetBillingConfig(c *fiber.Ctx) error {
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetBillingConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.InvoiceService.SetBillingConfig(input); err != nil {
		logger.LogError("SetBillingConfig: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to set billing config"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
