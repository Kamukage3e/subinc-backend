package discount

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// NewDiscountHandler creates a new discount handler with the necessary services
func NewDiscountHandler(
	discountService DiscountService,
	couponService CouponService,
	creditService CreditService,
	accountService account.BillingAccountService,
	logger logger.Logger,
) *DiscountHandler {
	return &DiscountHandler{
		DiscountService: discountService,
		CouponService:   couponService,
		CreditService:   creditService,
		AccountService:  accountService,
		Logger:          logger,
	}
}

func (h *DiscountHandler) GetDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetDiscount: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	discount, err := h.DiscountService.GetDiscount(id)
	if err != nil {
		logger.LogError("GetDiscount: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(discount)
}

func (h *DiscountHandler) GetDiscountByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		logger.LogError("GetDiscountByCode: code required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	discount, err := h.DiscountService.GetDiscountByCode(code)
	if err != nil {
		logger.LogError("GetDiscountByCode: failed", logger.ErrorField(err), logger.String("code", code))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(discount)
}

func (h *DiscountHandler) ListDiscounts(c *fiber.Ctx) error {
	activeOnly := c.QueryBool("active_only", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	discounts, err := h.DiscountService.ListDiscounts(activeOnly, page, pageSize)
	if err != nil {
		logger.LogError("ListDiscounts: failed", logger.ErrorField(err), logger.Bool("active_only", activeOnly))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(fiber.Map{"discounts": discounts, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) CreateDiscount(c *fiber.Ctx) error {
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	if input.ID == "" {
		input.ID = uuid.NewString()
	}
	if input.Metadata == "" {
		input.Metadata = "{}"
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	discount, err := h.DiscountService.CreateDiscount(input)
	if err != nil {
		logger.LogError("CreateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusCreated).JSON(discount)
}

func (h *DiscountHandler) UpdateDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateDiscount: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	var input Discount
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDiscount: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	input.ID = id
	if input.Code == "" {
		logger.LogError("UpdateDiscount: code required for update", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	if input.Metadata == "" {
		input.Metadata = "{}"
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateDiscount: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	discount, err := h.DiscountService.UpdateDiscount(input)
	if err != nil {
		logger.LogError("UpdateDiscount: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(discount)
}

func (h *DiscountHandler) DeleteDiscount(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteDiscount: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	if err := h.DiscountService.DeleteDiscount(id); err != nil {
		logger.LogError("DeleteDiscount: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) CreateCoupon(c *fiber.Ctx) error {
	var input Coupon
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	if input.ID == "" {
		input.ID = uuid.NewString()
	}
	if input.Metadata == "" {
		input.Metadata = "{}"
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = time.Now().UTC()
	}
	if input.UpdatedAt.IsZero() {
		input.UpdatedAt = input.CreatedAt
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	coupon, err := h.CouponService.CreateCoupon(input)
	if err != nil {
		logger.LogError("CreateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.Status(fiber.StatusCreated).JSON(coupon)
}

func (h *DiscountHandler) UpdateCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateCoupon: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	var input Coupon
	input.ID = id
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateCoupon: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	if input.ID == "" {
		logger.LogError("UpdateCoupon: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateCoupon: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	coupon, err := h.CouponService.UpdateCoupon(input)
	if err != nil {
		logger.LogError("UpdateCoupon: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.JSON(coupon)
}

func (h *DiscountHandler) DeleteCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCoupon: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	if err := h.CouponService.DeleteCoupon(id); err != nil {
		logger.LogError("DeleteCoupon: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) GetCoupon(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetCoupon: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	coupon, err := h.CouponService.GetCoupon(id)
	if err != nil {
		logger.LogError("GetCoupon: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(coupon)
}

func (h *DiscountHandler) GetCouponByCode(c *fiber.Ctx) error {
	code := c.Params("code")
	if code == "" {
		logger.LogError("GetCouponByCode: code required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required parameter"})
	}
	coupon, err := h.CouponService.GetCouponByCode(code)
	if err != nil {
		logger.LogError("GetCouponByCode: failed", logger.ErrorField(err), logger.String("code", code))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process request"})
	}
	return c.JSON(coupon)
}

func (h *DiscountHandler) ListCoupons(c *fiber.Ctx) error {
	discountID := c.Query("discount_id")
	isActive := c.QueryBool("is_active", false)
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	coupons, err := h.CouponService.ListCoupons(discountID, &isActive, page, pageSize)
	if err != nil {
		logger.LogError("ListCoupons: failed", logger.ErrorField(err), logger.String("discount_id", discountID))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(fiber.Map{"coupons": coupons, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) CreateCredit(c *fiber.Ctx) error {
	var input Credit
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateCredit: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		input.ID = uuid.NewString()
	}
	if input.Metadata == "" {
		input.Metadata = "{}"
	}
	if input.CreatedAt.IsZero() {
		input.CreatedAt = time.Now().UTC()
	}
	if input.UpdatedAt.IsZero() {
		input.UpdatedAt = input.CreatedAt
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateCredit: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	res, err := h.AccountService.Get(c.Context(), account.AccountTypeProject, input.AccountID)
	if err != nil {
		logger.LogError("CreateCredit: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	account, _ := res.(account.ProjectBillingAccount)
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(account.Currency))
		if currency == "" {
			logger.LogError("CreateCredit: no currency set for credit or account")
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for credit or account"})
		}
		input.Currency = currency
	}
	if input.Currency != account.Currency && account.Currency != "" {
		rate, rerr := h.CreditService.GetExchangeRate(c.Context(), input.Currency, account.Currency)
		if rerr != nil || rate.Rate <= 0 {
			logger.LogError("CreateCredit: no valid exchange rate", logger.ErrorField(rerr), logger.String("from", input.Currency), logger.String("to", account.Currency))
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

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.Status(fiber.StatusCreated).JSON(credit)
}

func (h *DiscountHandler) UpdateCredit(c *fiber.Ctx) error {
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
		return c.JSON(fiber.ErrBadRequest)
	}
	credit, err := h.CreditService.UpdateCredit(input)
	if err != nil {
		logger.LogError("UpdateCredit: failed", logger.ErrorField(err), logger.Any("input", input))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(credit)
}

func (h *DiscountHandler) PatchCredit(c *fiber.Ctx) error {
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

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) DeleteCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteCredit: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.CreditService.DeleteCredit(id); err != nil {
		logger.LogError("DeleteCredit: failed", logger.ErrorField(err), logger.String("id", id))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *DiscountHandler) GetCredit(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetCredit: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	credit, err := h.CreditService.GetCredit(id)
	if err != nil {
		logger.LogError("GetCredit: not found", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(credit)
}

func (h *DiscountHandler) ListCredits(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	credits, err := h.CreditService.ListCredits(accountID, invoiceID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListCredits: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("invoice_id", invoiceID), logger.String("status", status))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(fiber.Map{"credits": credits, "page": page, "page_size": pageSize})
}

func (h *DiscountHandler) RedeemCoupon(c *fiber.Ctx) error {
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

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(coupon)
}

func (h *DiscountHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(id); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", id))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Plugin management handlers

// ListDiscountPlugins returns all registered discount plugins
func (h *DiscountHandler) ListDiscountPlugins(c *fiber.Ctx) error {
	pluginNames := DiscountPlugins.List()

	return c.JSON(fiber.Map{
		"plugins": pluginNames,
	})
}

// GetDiscountPlugin returns details about a specific discount plugin
func (h *DiscountHandler) GetDiscountPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("GetDiscountPlugin: Plugin name is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	plugin, exists := DiscountPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("GetDiscountPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Discount plugin '%s' not found", pluginName),
		})
	}

	return c.JSON(fiber.Map{
		"name":         plugin.Name(),
		"version":      plugin.Version(),
		"capabilities": plugin.Capabilities(),
	})
}

// ConfigureDiscountPlugin configures a discount plugin
func (h *DiscountHandler) ConfigureDiscountPlugin(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("ConfigureDiscountPlugin: Tenant ID is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Tenant ID is required",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigureDiscountPlugin: Plugin name is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	// Check if the plugin exists
	plugin, exists := DiscountPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("ConfigureDiscountPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Discount plugin '%s' not found", pluginName),
		})
	}

	// Parse the configuration
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("ConfigureDiscountPlugin: Invalid configuration format", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Initialize the plugin with the configuration
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("ConfigureDiscountPlugin: Failed to initialize plugin", logger.ErrorField(err), logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to initialize plugin: %v", err),
		})
	}

	// Store the configuration in the database
	// This would typically be done via a store method

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Discount plugin '%s' configured successfully", pluginName),
	})
}

// DisableDiscountPlugin disables a discount plugin by name
func (h *DiscountHandler) DisableDiscountPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisableDiscountPlugin: Plugin name is required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Plugin name is required"})
	}
	// If runtime disable is not supported, return 501
	logger.LogError("DisableDiscountPlugin: not implemented for this plugin type", logger.String("plugin_name", pluginName))
	return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": "DisableDiscountPlugin not implemented for this plugin type"})
}
