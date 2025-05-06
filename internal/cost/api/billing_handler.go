package api

import (
	"context"
	"encoding/json"
	"net/http"

	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/idencode"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/spf13/viper"
)



func NewBillingHandler(
	svc service.BillingService,
	couponSvc service.CouponService,
	creditSvc service.CreditService,
	refundSvc service.RefundService,
	paymentMethodSvc service.PaymentMethodService,
	subscriptionSvc service.SubscriptionService,
	webhookEventSvc service.WebhookEventService,
	invoiceAdjustmentSvc service.InvoiceAdjustmentService,
	logger *logger.Logger,
) *BillingHandler {
	return &BillingHandler{
		service:                  svc,
		couponService:            couponSvc,
		creditService:            creditSvc,
		refundService:            refundSvc,
		paymentMethodService:     paymentMethodSvc,
		subscriptionService:      subscriptionSvc,
		webhookEventService:      webhookEventSvc,
		invoiceAdjustmentService: invoiceAdjustmentSvc,
	}
}



func (h *BillingHandler) CreateAccount(c *fiber.Ctx) error {
	var input service.CreateAccountInput
	if err := c.BodyParser(&input.Account); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreateAccount(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Account.ID = encodeID(out.Account.ID)
	return c.Status(http.StatusCreated).JSON(out.Account)
}

func (h *BillingHandler) UpdateAccount(c *fiber.Ctx) error {
	var input service.UpdateAccountInput
	if err := c.BodyParser(&input.Account); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.Account.ID = c.Params("id")
	out, err := h.service.UpdateAccount(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Account.ID = encodeID(out.Account.ID)
	return c.JSON(out.Account)
}

func (h *BillingHandler) GetAccount(c *fiber.Ctx) error {
	input := service.GetAccountInput{ID: c.Params("id")}
	out, err := h.service.GetAccount(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	out.Account.ID = encodeID(out.Account.ID)
	return c.JSON(out.Account)
}

func (h *BillingHandler) ListAccounts(c *fiber.Ctx) error {
	input := service.ListAccountsInput{
		TenantID: c.Query("tenant_id"),
		Page:     c.QueryInt("page", 1),
		PageSize: c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListAccounts(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&out.Accounts)
	return c.JSON(out)
}

func (h *BillingHandler) CreatePlan(c *fiber.Ctx) error {
	var input service.CreatePlanInput
	if err := c.BodyParser(&input.Plan); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreatePlan(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Plan.ID = encodeID(out.Plan.ID)
	return c.Status(http.StatusCreated).JSON(out.Plan)
}

func (h *BillingHandler) UpdatePlan(c *fiber.Ctx) error {
	var input service.UpdatePlanInput
	if err := c.BodyParser(&input.Plan); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.Plan.ID = c.Params("id")
	out, err := h.service.UpdatePlan(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Plan.ID = encodeID(out.Plan.ID)
	return c.JSON(out.Plan)
}

func (h *BillingHandler) GetPlan(c *fiber.Ctx) error {
	input := service.GetPlanInput{ID: c.Params("id")}
	out, err := h.service.GetPlan(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	out.Plan.ID = encodeID(out.Plan.ID)
	return c.JSON(out.Plan)
}

func (h *BillingHandler) ListPlans(c *fiber.Ctx) error {
	input := service.ListPlansInput{
		ActiveOnly: c.QueryBool("active_only", false),
		Page:       c.QueryInt("page", 1),
		PageSize:   c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListPlans(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&out.Plans)
	return c.JSON(out)
}

func (h *BillingHandler) CreateUsage(c *fiber.Ctx) error {
	var input service.CreateUsageInput
	if err := c.BodyParser(&input.Usage); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreateUsage(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(out.Usage)
}

func (h *BillingHandler) ListUsage(c *fiber.Ctx) error {
	startTimeStr := c.Query("start_time")
	endTimeStr := c.Query("end_time")
	var startTime, endTime time.Time
	var err error
	if startTimeStr != "" {
		startTime, err = time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid start_time"})
		}
	}
	if endTimeStr != "" {
		endTime, err = time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid end_time"})
		}
	}
	input := service.ListUsageInput{
		AccountID: c.Query("account_id"),
		StartTime: startTime,
		EndTime:   endTime,
		Page:      c.QueryInt("page", 1),
		PageSize:  c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListUsage(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingHandler) CreateInvoice(c *fiber.Ctx) error {
	var input service.CreateInvoiceInput
	if err := c.BodyParser(&input.Invoice); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreateInvoice(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Invoice.ID = encodeID(out.Invoice.ID)
	return c.Status(http.StatusCreated).JSON(out.Invoice)
}

func (h *BillingHandler) UpdateInvoice(c *fiber.Ctx) error {
	var input service.UpdateInvoiceInput
	if err := c.BodyParser(&input.Invoice); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.Invoice.ID = c.Params("id")
	out, err := h.service.UpdateInvoice(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Invoice.ID = encodeID(out.Invoice.ID)
	return c.JSON(out.Invoice)
}

func (h *BillingHandler) GetInvoice(c *fiber.Ctx) error {
	input := service.GetInvoiceInput{ID: c.Params("id")}
	out, err := h.service.GetInvoice(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	out.Invoice.ID = encodeID(out.Invoice.ID)
	return c.JSON(out.Invoice)
}

func (h *BillingHandler) ListInvoices(c *fiber.Ctx) error {
	input := service.ListInvoicesInput{
		AccountID: c.Query("account_id"),
		Status:    c.Query("status"),
		Page:      c.QueryInt("page", 1),
		PageSize:  c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListInvoices(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&out.Invoices)
	return c.JSON(fiber.Map{"invoices": out.Invoices, "total": out.Total, "page": input.Page, "page_size": input.PageSize})
}

func (h *BillingHandler) CreatePayment(c *fiber.Ctx) error {
	var input service.CreatePaymentInput
	if err := c.BodyParser(&input.Payment); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreatePayment(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Payment.ID = encodeID(out.Payment.ID)
	return c.Status(http.StatusCreated).JSON(out.Payment)
}

func (h *BillingHandler) UpdatePayment(c *fiber.Ctx) error {
	var input service.UpdatePaymentInput
	if err := c.BodyParser(&input.Payment); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.Payment.ID = c.Params("id")
	out, err := h.service.UpdatePayment(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	out.Payment.ID = encodeID(out.Payment.ID)
	return c.JSON(out.Payment)
}

func (h *BillingHandler) GetPayment(c *fiber.Ctx) error {
	input := service.GetPaymentInput{ID: c.Params("id")}
	out, err := h.service.GetPayment(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	out.Payment.ID = encodeID(out.Payment.ID)
	return c.JSON(out.Payment)
}

func (h *BillingHandler) ListPayments(c *fiber.Ctx) error {
	input := service.ListPaymentsInput{
		InvoiceID: c.Query("invoice_id"),
		Page:      c.QueryInt("page", 1),
		PageSize:  c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListPayments(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&out.Payments)
	return c.JSON(out)
}

func (h *BillingHandler) CreateAuditLog(c *fiber.Ctx) error {
	var input service.CreateAuditLogInput
	if err := c.BodyParser(&input.AuditLog); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	out, err := h.service.CreateAuditLog(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(out.AuditLog)
}

func (h *BillingHandler) ListAuditLogs(c *fiber.Ctx) error {
	startTimeStr := c.Query("start_time")
	endTimeStr := c.Query("end_time")
	var startTime, endTime time.Time
	var err error
	if startTimeStr != "" {
		startTime, err = time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid start_time"})
		}
	}
	if endTimeStr != "" {
		endTime, err = time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid end_time"})
		}
	}
	input := service.ListAuditLogsInput{
		AccountID: c.Query("account_id"),
		Action:    c.Query("action"),
		StartTime: startTime,
		EndTime:   endTime,
		Page:      c.QueryInt("page", 1),
		PageSize:  c.QueryInt("page_size", 100),
	}
	out, err := h.service.ListAuditLogs(context.Background(), input)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(out)
}

func (h *BillingHandler) SearchAuditLogs(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	action := c.Query("action")
	startTimeStr := c.Query("start_time")
	endTimeStr := c.Query("end_time")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	var startTime, endTime time.Time
	var err error
	if startTimeStr != "" {
		startTime, err = time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid start_time"})
		}
	}
	if endTimeStr != "" {
		endTime, err = time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid end_time"})
		}
	}
	input := service.ListAuditLogsInput{
		AccountID: accountID,
		Action:    action,
		StartTime: startTime,
		EndTime:   endTime,
		Page:      page,
		PageSize:  pageSize,
	}
	logs, err := h.service.ListAuditLogs(c.Context(), input)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"audit_logs": logs, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateDiscount(c *fiber.Ctx) error {
	var discount service.DiscountInput
	if err := c.BodyParser(&discount); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.service.CreateDiscount(context.Background(), discount.Discount); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	discount.Discount.ID = encodeID(discount.Discount.ID)
	return c.Status(http.StatusCreated).JSON(discount.Discount)
}

func (h *BillingHandler) UpdateDiscount(c *fiber.Ctx) error {
	var discount service.DiscountInput
	if err := c.BodyParser(&discount); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	discount.Discount.ID = c.Params("id")
	if err := h.service.UpdateDiscount(context.Background(), discount.Discount); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(discount.Discount)
}

func (h *BillingHandler) DeleteDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.service.DeleteDiscount(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	discount, err := h.service.GetDiscountByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	discount.ID = encodeID(discount.ID)
	return c.JSON(discount)
}

func (h *BillingHandler) GetDiscountByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	discount, err := h.service.GetDiscountByCode(context.Background(), code)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(discount)
}

func (h *BillingHandler) ListDiscounts(c *fiber.Ctx) error {
	var isActive *bool
	if c.Query("is_active") != "" {
		b := c.QueryBool("is_active", false)
		isActive = &b
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	discounts, total, err := h.service.ListDiscounts(context.Background(), isActive, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&discounts)
	return c.JSON(fiber.Map{"discounts": discounts, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateCoupon(c *fiber.Ctx) error {
	var input CouponInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.couponService.CreateCoupon(context.Background(), input.Coupon); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	input.Coupon.ID = encodeID(input.Coupon.ID)
	return c.Status(http.StatusCreated).JSON(input.Coupon)
}

func (h *BillingHandler) UpdateCoupon(c *fiber.Ctx) error {
	var input CouponInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.Coupon.ID = c.Params("id")
	if err := h.couponService.UpdateCoupon(context.Background(), input.Coupon); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(input.Coupon)
}

func (h *BillingHandler) DeleteCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.couponService.DeleteCoupon(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	coupon, err := h.couponService.GetCouponByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	coupon.ID = encodeID(coupon.ID)
	return c.JSON(coupon)
}

func (h *BillingHandler) GetCouponByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	coupon, err := h.couponService.GetCouponByCode(context.Background(), code)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(coupon)
}

func (h *BillingHandler) ListCoupons(c *fiber.Ctx) error {
	discountID := c.Query("discount_id")
	var isActive *bool
	if c.Query("is_active") != "" {
		b := c.QueryBool("is_active", false)
		isActive = &b
	}
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	coupons, total, err := h.couponService.ListCoupons(context.Background(), discountID, isActive, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&coupons)
	return c.JSON(fiber.Map{"coupons": coupons, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateCredit(c *fiber.Ctx) error {
	var credit domain.Credit
	if err := c.BodyParser(&credit); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.creditService.ApplyCredit(context.Background(), &credit); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	credit.ID = encodeID(credit.ID)
	return c.Status(http.StatusCreated).JSON(credit)
}

func (h *BillingHandler) UpdateCredit(c *fiber.Ctx) error {
	var credit domain.Credit
	if err := c.BodyParser(&credit); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	credit.ID = c.Params("id")
	credit.UpdatedAt = time.Now().UTC()
	if err := h.creditService.ApplyCredit(context.Background(), &credit); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	credit.ID = encodeID(credit.ID)
	return c.JSON(credit)
}

func (h *BillingHandler) DeleteCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.creditService.ExpireCredit(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	credit, err := h.creditService.GetCreditByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	credit.ID = encodeID(credit.ID)
	return c.JSON(credit)
}

func (h *BillingHandler) ListCredits(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	credits, total, err := h.creditService.ListCredits(context.Background(), accountID, invoiceID, status, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&credits)
	return c.JSON(fiber.Map{"credits": credits, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateRefund(c *fiber.Ctx) error {
	var refund domain.Refund
	if err := c.BodyParser(&refund); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.refundService.CreateRefund(context.Background(), &refund); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	refund.ID = encodeID(refund.ID)
	return c.Status(http.StatusCreated).JSON(refund)
}

func (h *BillingHandler) UpdateRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.refundService.ProcessRefund(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusOK)
}

func (h *BillingHandler) DeleteRefund(c *fiber.Ctx) error {
	// Refunds are not deleted, only processed or failed. Return 405.
	return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"error": "refunds cannot be deleted"})
}

func (h *BillingHandler) GetRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	refund, err := h.refundService.GetRefundByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	refund.ID = encodeID(refund.ID)
	return c.JSON(refund)
}

func (h *BillingHandler) ListRefunds(c *fiber.Ctx) error {
	paymentID := c.Query("payment_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	refunds, total, err := h.refundService.ListRefunds(context.Background(), paymentID, invoiceID, status, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&refunds)
	return c.JSON(fiber.Map{"refunds": refunds, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	var req struct {
		PaymentMethod domain.PaymentMethod `json:"payment_method"`
		PaymentData   map[string]string    `json:"payment_data"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.paymentMethodService.AddPaymentMethod(context.Background(), &req.PaymentMethod, req.PaymentData); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	req.PaymentMethod.ID = encodeID(req.PaymentMethod.ID)
	return c.Status(http.StatusCreated).JSON(req.PaymentMethod)
}

func (h *BillingHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	var pm domain.PaymentMethod
	if err := c.BodyParser(&pm); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	pm.ID = c.Params("id")
	pm.UpdatedAt = time.Now().UTC()
	if err := h.paymentMethodService.UpdatePaymentMethod(context.Background(), &pm); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(pm)
}

func (h *BillingHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.paymentMethodService.RemovePaymentMethod(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	pm, err := h.paymentMethodService.GetPaymentMethodByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	pm.ID = encodeID(pm.ID)
	return c.JSON(pm)
}

func (h *BillingHandler) ListPaymentMethods(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	methods, total, err := h.paymentMethodService.ListPaymentMethods(context.Background(), accountID, status, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&methods)
	return c.JSON(fiber.Map{"payment_methods": methods, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateSubscription(c *fiber.Ctx) error {
	var sub domain.Subscription
	if err := c.BodyParser(&sub); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.subscriptionService.CreateSubscription(context.Background(), &sub); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	sub.ID = encodeID(sub.ID)
	return c.Status(http.StatusCreated).JSON(sub)
}

func (h *BillingHandler) UpdateSubscription(c *fiber.Ctx) error {
	var sub domain.Subscription
	if err := c.BodyParser(&sub); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	sub.ID = c.Params("id")
	sub.UpdatedAt = time.Now().UTC()
	if err := h.subscriptionService.UpdateSubscription(context.Background(), &sub); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(sub)
}

func (h *BillingHandler) DeleteSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.subscriptionService.CancelSubscription(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	sub, err := h.subscriptionService.GetSubscriptionByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	sub.ID = encodeID(sub.ID)
	return c.JSON(sub)
}

func (h *BillingHandler) ListSubscriptions(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	subs, total, err := h.subscriptionService.ListSubscriptions(context.Background(), accountID, status, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&subs)
	return c.JSON(fiber.Map{"subscriptions": subs, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateWebhookEvent(c *fiber.Ctx) error {
	var event domain.WebhookEvent
	if err := c.BodyParser(&event); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.webhookEventService.ReceiveEvent(context.Background(), &event); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	event.ID = encodeID(event.ID)
	return c.Status(http.StatusCreated).JSON(event)
}

func (h *BillingHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.webhookEventService.ProcessEvent(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusOK)
}

func (h *BillingHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.webhookEventService.RetryEvent(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusOK)
}

func (h *BillingHandler) GetWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	event, err := h.webhookEventService.GetWebhookEventByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	event.ID = encodeID(event.ID)
	return c.JSON(event)
}

func (h *BillingHandler) ListWebhookEvents(c *fiber.Ctx) error {
	provider := c.Query("provider")
	eventType := c.Query("event_type")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	events, total, err := h.webhookEventService.ListWebhookEvents(context.Background(), provider, status, eventType, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&events)
	return c.JSON(fiber.Map{"webhook_events": events, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) CreateInvoiceAdjustment(c *fiber.Ctx) error {
	var adj domain.InvoiceAdjustment
	if err := c.BodyParser(&adj); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.invoiceAdjustmentService.ApplyAdjustment(context.Background(), &adj); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	adj.ID = encodeID(adj.ID)
	return c.Status(http.StatusCreated).JSON(adj)
}

func (h *BillingHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	// Invoice adjustments are not updated, only created or deleted. Return 405.
	return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"error": "invoice adjustments cannot be updated"})
}

func (h *BillingHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	// Invoice adjustments are not deleted, only expired or reversed. Return 405.
	return c.Status(http.StatusMethodNotAllowed).JSON(fiber.Map{"error": "invoice adjustments cannot be deleted"})
}

func (h *BillingHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	adj, err := h.invoiceAdjustmentService.GetInvoiceAdjustmentByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	adj.ID = encodeID(adj.ID)
	return c.JSON(adj)
}

func (h *BillingHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	invoiceID := c.Query("invoice_id")
	typeStr := c.Query("type")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	adjs, total, err := h.invoiceAdjustmentService.ListInvoiceAdjustments(context.Background(), invoiceID, typeStr, page, pageSize)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	encodeIDs(&adjs)
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "total": total, "page": page, "page_size": pageSize})
}

func (h *BillingHandler) PatchCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		Action string  `json:"action"` // "consume" or "expire"
		Amount float64 `json:"amount,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Action == "consume" {
		if req.Amount <= 0 {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "amount must be > 0"})
		}
		if err := h.creditService.ConsumeCredit(context.Background(), id, req.Amount); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(http.StatusNoContent)
	}
	if req.Action == "expire" {
		if err := h.creditService.ExpireCredit(context.Background(), id); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(http.StatusNoContent)
	}
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid action"})
}

func (h *BillingHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		SetDefault *bool  `json:"set_default,omitempty"`
		Status     string `json:"status,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.SetDefault != nil && *req.SetDefault {
		pm, err := h.paymentMethodService.GetPaymentMethodByID(context.Background(), id)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		if err := h.paymentMethodService.SetDefaultPaymentMethod(context.Background(), pm.AccountID, id); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(http.StatusNoContent)
	}
	if req.Status != "" {
		pm, err := h.paymentMethodService.GetPaymentMethodByID(context.Background(), id)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		pm.Status = req.Status
		pm.UpdatedAt = time.Now().UTC()
		if err := h.paymentMethodService.UpdatePaymentMethod(context.Background(), pm); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(pm)
	}
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "no valid patch operation"})
}

func (h *BillingHandler) PatchSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		Status          string     `json:"status,omitempty"`
		ScheduledPlanID string     `json:"scheduled_plan_id,omitempty"`
		ChangeAt        *time.Time `json:"change_at,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.Status != "" {
		sub, err := h.subscriptionService.GetSubscriptionByID(context.Background(), id)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		sub.Status = req.Status
		sub.UpdatedAt = time.Now().UTC()
		if err := h.subscriptionService.UpdateSubscription(context.Background(), sub); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(sub)
	}
	if req.ScheduledPlanID != "" && req.ChangeAt != nil {
		if err := h.subscriptionService.SchedulePlanChange(context.Background(), id, req.ScheduledPlanID, *req.ChangeAt); err != nil {
			return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(http.StatusNoContent)
	}
	return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "no valid patch operation"})
}

func (h *BillingHandler) ChangePlanSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		PlanID   string     `json:"plan_id"`
		ChangeAt *time.Time `json:"change_at,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.PlanID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	changeAt := time.Now().UTC()
	if req.ChangeAt != nil {
		changeAt = *req.ChangeAt
	}
	if err := h.subscriptionService.SchedulePlanChange(context.Background(), id, req.PlanID, changeAt); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) CancelSubscriptionNow(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.subscriptionService.CancelSubscription(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) ResumeSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	sub, err := h.subscriptionService.GetSubscriptionByID(context.Background(), id)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if sub.Status != "canceled" && sub.Status != "dunning" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "subscription not resumable"})
	}
	sub.Status = "active"
	sub.UpdatedAt = time.Now().UTC()
	if err := h.subscriptionService.UpdateSubscription(context.Background(), sub); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(sub)
}

func (h *BillingHandler) ReceiveWebhook(c *fiber.Ctx) error {
	provider := c.Params("provider")
	var event domain.WebhookEvent
	if err := c.BodyParser(&event); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	event.Provider = provider
	event.ReceivedAt = time.Now().UTC()
	if err := h.webhookEventService.ReceiveEvent(context.Background(), &event); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(http.StatusCreated).JSON(event)
}

func (h *BillingHandler) GetInvoicePreview(c *fiber.Ctx) error {
	accountID := c.Params("id")
	if accountID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "account id required"})
	}
	invoice, err := h.subscriptionService.NextInvoicePreview(context.Background(), accountID)
	if err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(invoice)
}

func (h *BillingHandler) RedeemCoupon(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "coupon code required"})
	}
	coupon, err := h.couponService.GetCouponByCode(context.Background(), code)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	if !coupon.IsActive || time.Now().Before(coupon.StartAt) || time.Now().After(coupon.EndAt) {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": "coupon not active or expired"})
	}
	if coupon.MaxRedemptions > 0 && coupon.Redeemed >= coupon.MaxRedemptions {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": "coupon max redemptions reached"})
	}
	coupon.Redeemed++
	coupon.UpdatedAt = time.Now().UTC()
	if err := h.couponService.UpdateCoupon(context.Background(), coupon); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(coupon)
}

func (h *BillingHandler) UpgradeNowSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if req.PlanID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "plan_id required"})
	}
	if err := h.subscriptionService.UpgradeNow(context.Background(), id, req.PlanID); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	invoiceID := c.Params("id")
	if invoiceID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invoice id required"})
	}
	if err := h.creditService.ApplyCreditsToInvoice(context.Background(), invoiceID); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *BillingHandler) GetBillingConfig(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"tax_rate":    viper.GetString("BILLING_TAX_RATE"),
		"fixed_fee":   viper.GetString("BILLING_FIXED_FEE"),
		"percent_fee": viper.GetString("BILLING_PERCENT_FEE"),
	})
}

func (h *BillingHandler) SetBillingConfig(c *fiber.Ctx) error {
	var req struct {
		TaxRate    string `json:"tax_rate"`
		FixedFee   string `json:"fixed_fee"`
		PercentFee string `json:"percent_fee"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	oldConfig := fiber.Map{
		"tax_rate":    viper.GetString("BILLING_TAX_RATE"),
		"fixed_fee":   viper.GetString("BILLING_FIXED_FEE"),
		"percent_fee": viper.GetString("BILLING_PERCENT_FEE"),
	}

	newConfig := fiber.Map{
		"tax_rate":    viper.GetString("BILLING_TAX_RATE"),
		"fixed_fee":   viper.GetString("BILLING_FIXED_FEE"),
		"percent_fee": viper.GetString("BILLING_PERCENT_FEE"),
	}
	actorID := "system"
	if v := c.Locals("actor_id"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			actorID = s
		}
	}
	details := fiber.Map{
		"old": oldConfig,
		"new": newConfig,
	}
	detailsJSON, _ := json.Marshal(details)
	_, _ = h.service.CreateAuditLog(context.Background(), service.CreateAuditLogInput{
		AuditLog: &domain.AuditLog{
			ID:        uuid.NewString(),
			ActorID:   actorID,
			Action:    "billing_config_change",
			TargetID:  "billing_config",
			Timestamp: time.Now().UTC(),
			Details:   string(detailsJSON),
		},
	})
	return c.JSON(newConfig)
}

func (h *BillingHandler) CreateManualAdjustment(c *fiber.Ctx) error {
	var req struct {
		AccountID string  `json:"account_id"`
		Amount    float64 `json:"amount"`
		Reason    string  `json:"reason"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.service.CreateManualAdjustment(c.Context(), req.AccountID, req.Amount, req.Reason)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(result)
}

func (h *BillingHandler) CreateManualRefund(c *fiber.Ctx) error {
	var req struct {
		PaymentID string  `json:"payment_id"`
		Amount    float64 `json:"amount"`
		Reason    string  `json:"reason"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.service.CreateManualRefund(c.Context(), req.PaymentID, req.Amount, req.Reason)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(result)
}

func (h *BillingHandler) PerformAccountAction(c *fiber.Ctx) error {
	var req struct {
		AccountID string `json:"account_id"`
		Action    string `json:"action"`
		Reason    string `json:"reason"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid input"})
	}
	result, err := h.service.PerformAccountAction(c.Context(), req.AccountID, req.Action, req.Reason)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(result)
}

func (h *BillingHandler) DeletePlan(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.service.DeletePlan(context.Background(), id); err != nil {
		return c.Status(http.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}

func encodeID(id string) string {
	idHash, err := idencode.Encode(id)
	if err != nil {
		return ""
	}
	return idHash
}

func encodeIDs(objs interface{}) {
	switch v := objs.(type) {
	case *[]domain.BillingAccount:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.BillingPlan:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Invoice:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Payment:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Credit:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Refund:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.PaymentMethod:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Subscription:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.WebhookEvent:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.InvoiceAdjustment:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Coupon:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	case *[]domain.Discount:
		for i := range *v {
			(*v)[i].ID = encodeID((*v)[i].ID)
		}
	}
}
