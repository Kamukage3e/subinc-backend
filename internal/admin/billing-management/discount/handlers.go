package discount

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// NewDiscountHandler creates a new discount handler with the necessary services
func NewDiscountHandler(
	discountService DiscountService,
	couponService CouponService,
	creditService CreditService,
	accountService account.AccountService,
	rbacService rbac_management.RBACService,
	logger logger.Logger,
) *DiscountHandler {
	return &DiscountHandler{
		DiscountService: discountService,
		CouponService:   couponService,
		CreditService:   creditService,
		AccountService:  accountService,
		RBACService:     rbacService,
		Logger:          logger,
	}
}

func (h *DiscountHandler) GetDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

func (h *DiscountHandler) GetDiscountByCode(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

func (h *DiscountHandler) ListDiscounts(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_discount", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	activeOnly := c.QueryBool("active_only", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	discounts, err := h.DiscountService.ListDiscounts(activeOnly, page, pageSize)
	if err != nil {
		logger.LogError("ListDiscounts: failed", logger.ErrorField(err), logger.Bool("active_only", activeOnly))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"discounts": discounts, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) CreateDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	discount, err := h.DiscountService.CreateDiscount(input)
	if err != nil {
		logger.LogError("CreateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(discount)
}

func (h *DiscountHandler) UpdateDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateDiscount: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	discount, err := h.DiscountService.UpdateDiscount(input)
	if err != nil {
		logger.LogError("UpdateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(discount)
}

func (h *DiscountHandler) DeleteDiscount(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "discount", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteDiscount: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.DiscountService.DeleteDiscount(id); err != nil {
		logger.LogError("DeleteDiscount: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) CreateCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	coupon, err := h.CouponService.CreateCoupon(input)
	if err != nil {
		logger.LogError("CreateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(coupon)
}

func (h *DiscountHandler) UpdateCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateCoupon: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Coupon
	input.ID = id
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("UpdateCoupon: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	coupon, err := h.CouponService.UpdateCoupon(input)
	if err != nil {
		logger.LogError("UpdateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(coupon)
}

func (h *DiscountHandler) DeleteCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCoupon: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CouponService.DeleteCoupon(id); err != nil {
		logger.LogError("DeleteCoupon: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) GetCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

func (h *DiscountHandler) GetCouponByCode(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

func (h *DiscountHandler) ListCoupons(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_coupon", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	discountID := c.Query("discount_id")
	isActive := c.QueryBool("is_active", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	coupons, err := h.CouponService.ListCoupons(discountID, &isActive, page, pageSize)
	if err != nil {
		logger.LogError("ListCoupons: failed", logger.ErrorField(err), logger.String("discount_id", discountID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"coupons": coupons, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) CreateCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCredit: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.GetAccount(input.AccountID)
	if err != nil {
		logger.LogError("CreateCredit: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(account.Currency))
		if currency == "" {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for credit or account"})
		}
		input.Currency = currency
	}
	if input.Currency != account.Currency && account.Currency != "" {
		rate, rerr := h.CreditService.GetExchangeRate(c.Context(), input.Currency, account.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + account.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = account.Currency
	}
	credit, err := h.CreditService.CreateCredit(input)
	if err != nil {
		logger.LogError("CreateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(credit)
}

func (h *DiscountHandler) UpdateCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateCredit: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateCredit: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	credit, err := h.CreditService.UpdateCredit(input)
	if err != nil {
		logger.LogError("UpdateCredit: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(credit)
}

func (h *DiscountHandler) PatchCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "patch")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("PatchCredit: id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input struct {
		Action string  `json:"action"`
		Amount float64 `json:"amount"`
	}
	if err := c.BodyParser(&input); err != nil || input.Action == "" {
		logger.LogError("PatchCredit: action required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "action required"})
	}
	if err := h.CreditService.PatchCredit(id, input.Action, input.Amount); err != nil {
		logger.LogError("PatchCredit: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) DeleteCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCredit: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CreditService.DeleteCredit(id); err != nil {
		logger.LogError("DeleteCredit: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) GetCredit(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

func (h *DiscountHandler) ListCredits(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	accountID := c.Query("account_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	credits, err := h.CreditService.ListCredits(accountID, invoiceID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListCredits: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("invoice_id", invoiceID), logger.String("status", status))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"credits": credits, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) RedeemCoupon(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "coupon", "redeem")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("RedeemCoupon: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input struct {
		AccountID string `json:"account_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.AccountID == "" {
		logger.LogError("RedeemCoupon: account_id required", logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account_id required"})
	}
	coupon, err := h.CouponService.RedeemCoupon(id, input.AccountID)
	if err != nil {
		logger.LogError("RedeemCoupon: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(coupon)
}

func (h *DiscountHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "apply")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(id); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
