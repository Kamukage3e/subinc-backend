package billing_management

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"strings"

	"github.com/gofiber/fiber/v2"
	// "github.com/google/uuid"
	"github.com/jung-kurt/gofpdf"

	"os"

	"context"

	"encoding/json"
	"encoding/xml"

	"reflect"

	"strconv"

	"github.com/stripe/stripe-go/v75/webhook"
	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	discount "github.com/subinc/subinc-backend/internal/admin/billing-management/discount"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	tax "github.com/subinc/subinc-backend/internal/admin/billing-management/tax"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
)

// Payment, Refund, and PaymentMethod logic is now handled exclusively in internal/admin/billing-management/payment/handlers.go

func NewBillingHandler(
	store *PostgresStore,
	paymentStore payment.StoreInterface,
	invoiceService InvoiceService,
	reportService ReportService,
	manualAdjustmentService ManualAdjustmentService,
	creditService discount.CreditService,
	pluginManager *plugin.Manager,
	notify security_management.NotificationService,
	accountService account.BillingAccountService,
	taxService tax.TaxInfoService,
	invoiceExportService InvoiceExportService,
	webhookEventService WebhookEventService,
	webhookSubscriptionService WebhookSubscriptionService,
	dunningService DunningService,
) *BillingAdminHandler {
	// Validate all dependencies
	if store == nil || paymentStore == nil || invoiceService == nil || reportService == nil ||
		manualAdjustmentService == nil || creditService == nil || pluginManager == nil ||
		notify == nil || accountService == nil || taxService == nil || invoiceExportService == nil ||
		webhookEventService == nil || webhookSubscriptionService == nil || dunningService == nil {
		logger.LogFatal("NewBillingHandler: one or more dependencies are nil")
	}

	logr := logger.NewProduction(logger.InfoLevel, "json", false, "billing", "prod")

	handler := &BillingAdminHandler{
		Store:                      store,
		PaymentStore:               paymentStore,
		InvoiceService:             invoiceService,
		ReportService:              reportService,
		ManualAdjustmentService:    manualAdjustmentService,
		CreditService:              creditService,
		PluginManager:              pluginManager,
		Notify:                     notify,
		AccountService:             accountService,
		TaxService:                 taxService,
		InvoiceExportService:       invoiceExportService,
		WebhookEventService:        webhookEventService,
		WebhookSubscriptionService: webhookSubscriptionService,
		DunningService:             dunningService,
		Logger:                     logr,
	}

	handler.PluginManager.RegisterDefaultPlugins()
	logr.Info("Billing admin handler initialized successfully")
	return handler
}

func (h *BillingAdminHandler) CreateWebhookEvent(c *fiber.Ctx) error {
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateWebhookEvent: invalid request format", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format. Please check your request body."})
	}
	event, err := h.WebhookEventService.CreateWebhookEvent(input)
	if err != nil {
		logger.LogError("CreateWebhookEvent: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create webhook event"})
	}
	return c.Status(fiber.StatusCreated).JSON(event)
}

func (h *BillingAdminHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateWebhookEvent: missing webhook event ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateWebhookEvent: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	input.ID = id
	event, err := h.WebhookEventService.UpdateWebhookEvent(input)
	if err != nil {
		logger.LogError("UpdateWebhookEvent: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update webhook event"})
	}
	return c.JSON(event)
}

func (h *BillingAdminHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteWebhookEvent: missing webhook event ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.WebhookEventService.DeleteWebhookEvent(id); err != nil {
		logger.LogError("DeleteWebhookEvent: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete webhook event"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetWebhookEvent(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetWebhookEvent: missing webhook event ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	event, err := h.WebhookEventService.GetWebhookEvent(id)
	if err != nil {
		logger.LogError("GetWebhookEvent: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Webhook event not found"})
	}
	return c.JSON(event)
}

func (h *BillingAdminHandler) ListWebhookEvents(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	events, err := h.WebhookEventService.ListWebhookEvents(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListWebhookEvents: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("status", status))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"events": events, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreateInvoiceAdjustment(c *fiber.Ctx) error {
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format. Please check your request body."})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoiceAdjustment: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "error occured"})
	}
	adj, err := h.InvoiceAdjustmentService.CreateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("CreateInvoiceAdjustment: failed", logger.ErrorField(err))

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.Status(fiber.StatusCreated).JSON(adj)
}

func (h *BillingAdminHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateInvoiceAdjustment: missing adjustment ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	input.ID = id
	adj, err := h.InvoiceAdjustmentService.UpdateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("UpdateInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update invoice adjustment"})
	}
	return c.JSON(adj)
}

func (h *BillingAdminHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteInvoiceAdjustment: missing adjustment ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.InvoiceAdjustmentService.DeleteInvoiceAdjustment(id); err != nil {
		logger.LogError("DeleteInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete invoice adjustment"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetInvoiceAdjustment: missing adjustment ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	adj, err := h.InvoiceAdjustmentService.GetInvoiceAdjustment(id)
	if err != nil {
		logger.LogError("GetInvoiceAdjustment: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Invoice adjustment not found"})
	}
	return c.JSON(adj)
}

func (h *BillingAdminHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	invoiceID := c.Query("invoice_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	adjs, err := h.InvoiceAdjustmentService.ListInvoiceAdjustments(invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "page": page, "page_size": pageSize})
}

func (h *BillingAdminHandler) CreateManualAdjustment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateManualAdjustment: validation failed", logger.ErrorField(err))

		return c.JSON(fiber.ErrBadRequest)
	}
	err := h.ManualAdjustmentService.CreateManualAdjustment(id, input.Reason, input.Amount, input.Currency)
	if err != nil {
		logger.LogError("CreateManualAdjustment: failed", logger.ErrorField(err))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusCreated)
}

func (h *BillingAdminHandler) GetInvoicePreview(c *fiber.Ctx) error {
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoicePreview: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(c.Context(), input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": "failed to delete payment method"}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.JSON(fiber.ErrBadRequest)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(id); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", id))

		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	var input struct{}
	_ = c.BodyParser(&input) // Accepts empty body for consistency
	cfg, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
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

		return c.JSON(fiber.ErrBadRequest)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) CreateWebhookSubscription(c *fiber.Ctx) error {
	var input struct {
		URL         string   `json:"url"`
		Secret      string   `json:"secret"`
		Description string   `json:"description"`
		Events      []string `json:"events"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	err := h.WebhookSubscriptionService.CreateWebhookSubscription(input.URL, input.Secret, input.Description, input.Events)
	if err != nil {
		logger.LogError("", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.SendStatus(fiber.StatusCreated)
}

func (h *BillingAdminHandler) ListWebhookSubscriptions(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	out, err := h.WebhookSubscriptionService.ListWebhookSubscriptions(tenantID, page, pageSize)
	if err != nil {
		logger.LogError("", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	return c.JSON(out)
}

func (h *BillingAdminHandler) DeleteWebhookSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteWebhookSubscription: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if err := h.WebhookSubscriptionService.DeleteWebhookSubscription(id); err != nil {
		logger.LogError("DeleteWebhookSubscription: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete webhook subscription"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GetWebhookSubscription retrieves a webhook subscription by ID
func (h *BillingAdminHandler) GetWebhookSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetWebhookSubscription: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	sub, err := h.WebhookSubscriptionService.GetWebhookSubscription(id)
	if err != nil {
		logger.LogError("GetWebhookSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Webhook subscription not found"})
	}

	// Hide the secret in the response, replace with partial value
	if len(sub.Secret) > 4 {
		masked := strings.Repeat("*", len(sub.Secret)-4) + sub.Secret[len(sub.Secret)-4:]
		sub.Secret = masked
	}

	return c.JSON(sub)
}

// UpdateWebhookSubscription updates an existing webhook subscription
func (h *BillingAdminHandler) UpdateWebhookSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateWebhookSubscription: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	var input struct {
		URL    string   `json:"url"`
		Secret string   `json:"secret"`
		Events []string `json:"events"`
		Status string   `json:"status"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateWebhookSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	err := h.WebhookSubscriptionService.UpdateWebhookSubscription(id, input.URL, input.Secret, input.Events, input.Status)
	if err != nil {
		logger.LogError("UpdateWebhookSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update webhook subscription"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// TestWebhookSubscription sends a test event to a webhook
func (h *BillingAdminHandler) TestWebhookSubscription(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("TestWebhookSubscription: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	var input struct {
		EventType string                 `json:"event_type"`
		Payload   map[string]interface{} `json:"payload"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("TestWebhookSubscription: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	err := h.WebhookSubscriptionService.TestWebhookSubscription(id, input.EventType, input.Payload)
	if err != nil {
		logger.LogError("TestWebhookSubscription: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to test webhook subscription"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Test webhook sent successfully",
	})
}

// GetWebhookDeliveryLogs retrieves delivery logs for a webhook subscription
func (h *BillingAdminHandler) GetWebhookDeliveryLogs(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetWebhookDeliveryLogs: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)

	logs, err := h.WebhookSubscriptionService.GetWebhookDeliveryLogs(id, page, pageSize)
	if err != nil {
		logger.LogError("GetWebhookDeliveryLogs: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrBadRequest)
	}

	return c.JSON(fiber.Map{
		"logs": logs,
		"pagination": fiber.Map{
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// RetryWebhookDelivery retries a failed webhook delivery
func (h *BillingAdminHandler) RetryWebhookDelivery(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RetryWebhookDelivery: missing subscription ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}

	err := h.WebhookSubscriptionService.RetryWebhookDelivery(id)
	if err != nil {
		logger.LogError("RetryWebhookDelivery: failed", logger.ErrorField(err), logger.String("id", id))
		return c.JSON(fiber.ErrBadRequest)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Webhook delivery retry initiated",
	})
}

func (h *BillingAdminHandler) GetRevenueReport(c *fiber.Ctx) error {
	reportData, err := h.ReportService.GetRevenueReport(c.Context())
	if err != nil {
		logger.LogError("GetRevenueReport: failed to generate report", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}
	return c.JSON(reportData)
}

func (h *BillingAdminHandler) GetARReport(c *fiber.Ctx) error {
	if h.ReportService == nil {
		logger.LogError("GetARReport: ReportService is nil")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "ReportService not configured"})
	}
	// Get the accounts receivable report data
	reportData, err := h.ReportService.GetARReport(c.Context())
	if err != nil {
		logger.LogError("GetARReport: failed to generate report", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(reportData)
}

func (h *BillingAdminHandler) GetChurnReport(c *fiber.Ctx) error {
	if h.ReportService == nil {
		logger.LogError("GetChurnReport: ReportService is nil")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "ReportService not configured"})
	}
	// Get the churn report data
	reportData, err := h.ReportService.GetChurnReport(c.Context())
	if err != nil {
		logger.LogError("GetChurnReport: failed to generate report", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(reportData)
}

func (h *BillingAdminHandler) CreateInvoiceWithFeesAndTax(c *fiber.Ctx) error {
	// Parse the invoice data with fees and tax
	var input struct {
		Invoice    Invoice `json:"invoice"`
		FixedFee   float64 `json:"fixed_fee"`
		PercentFee float64 `json:"percent_fee"`
		TaxRate    float64 `json:"tax_rate"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoiceWithFeesAndTax: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	// Validate input parameters
	if input.Invoice.AccountID == "" {
		logger.LogError("CreateInvoiceWithFeesAndTax: missing account_id", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	// Process the invoice with fees and tax
	invoice, err := h.InvoiceExportService.CreateInvoiceWithFeesAndTax(
		c.Context(),
		input.Invoice,
		input.FixedFee,
		input.PercentFee,
		input.TaxRate,
	)
	if err != nil {
		logger.LogError("CreateInvoiceWithFeesAndTax: failed",
			logger.ErrorField(err),
			logger.String("account_id", input.Invoice.AccountID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(invoice)
}

func (h *BillingAdminHandler) CreateInvoice(c *fiber.Ctx) error {
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoice: validation failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrBadRequest)
	}
	res, err := h.AccountService.Get(c.Context(), account.AccountTypeProject, input.AccountID)
	if err != nil {
		logger.LogError("CreateInvoice: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	accountObj, _ := res.(account.ProjectBillingAccount)
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(accountObj.Currency))
		if currency == "" {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for invoice or account"})
		}
		input.Currency = currency
	}
	if input.Currency != accountObj.Currency && accountObj.Currency != "" {
		rate, rerr := h.Store.GetExchangeRate(c.Context(), input.Currency, accountObj.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + accountObj.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = accountObj.Currency
	}
	pluginName := "default"
	if cfg, err := h.TaxService.GetTaxPluginConfig(c.Context(), accountObj.TenantID); err == nil && cfg.PluginName != "" {
		pluginName = cfg.PluginName
	}

	// Get the tax plugin from the plugin manager
	plugin, ok := h.PluginManager.GetPlugin("tax", pluginName)
	if !ok {
		// If not found in the plugin manager, check if we can find the default plugin
		defaultPlugin, ok := h.PluginManager.GetPlugin("tax", "default")
		if !ok {
			// Register the built-in default plugin if needed
			defPlugin := tax.DefaultTaxPlugin{}
			if h.PluginManager != nil {
				_ = h.PluginManager.RegisterPlugin("tax", defPlugin)
				plugin, _ = h.PluginManager.GetPlugin("tax", "default")
			} else {
				// Last resort, use a direct instance
				h.Logger.Warn("Using direct DefaultTaxPlugin instance as fallback")
				plugin = defPlugin
			}
		} else {
			plugin = defaultPlugin
		}
	}

	if pluginName == "manual" {
		if input.TaxRate < 0 || input.TaxRate > 100 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "manual tax rate must be between 0 and 100"})
		}
	}
	input.PluginName = pluginName

	// Convert to tax.Invoice for the plugin
	taxInvoice := tax.Invoice{
		ID:               input.ID,
		AccountID:        input.AccountID,
		Amount:           input.Amount,
		Currency:         input.Currency,
		OriginalAmount:   input.OriginalAmount,
		OriginalCurrency: input.OriginalCurrency,
		Status:           input.Status,
		DueDate:          input.DueDate,
		CreatedAt:        input.CreatedAt,
		UpdatedAt:        input.UpdatedAt,
		TaxAmount:        input.TaxAmount,
		TaxRate:          input.TaxRate,
		Fees:             input.Fees,
	}

	// Convert to tax.Account for the plugin
	taxAccount := tax.Account{
		ID:        accountObj.ID,
		TenantID:  accountObj.TenantID,
		Email:     accountObj.Email,
		Status:    accountObj.Status,
		Currency:  accountObj.Currency,
		CreatedAt: accountObj.CreatedAt,
		UpdatedAt: accountObj.UpdatedAt,
	}

	// Type assert to the specific tax plugin interface
	taxPlugin, ok := plugin.(tax.TaxPlugin)
	if !ok {
		logger.LogError("CreateInvoice: plugin not compatible with TaxPlugin interface", logger.String("plugin", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "invalid tax plugin type"})
	}

	taxAmount, taxRate, terr := taxPlugin.CalculateTax(c.Context(), taxInvoice, taxAccount, accountObj.TenantID)
	if terr != nil {
		logger.LogError("CreateInvoice: tax plugin failed", logger.ErrorField(terr), logger.String("plugin", pluginName))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tax calculation failed: "})
	}
	input.TaxAmount = taxAmount
	input.TaxRate = taxRate
	invoice, err := h.InvoiceService.CreateInvoice(c.Context(), input)
	if err != nil {
		logger.LogError("CreateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))

		return c.JSON(fiber.ErrBadRequest)
	}
	if h.Notify != nil && accountObj.Email != "" {
		go func(inv Invoice) {
			res, accErr := h.AccountService.Get(c.Context(), account.AccountTypeProject, inv.AccountID)
			if accErr != nil || res == nil {
				logger.LogError("dunning.worker.notify.account_not_found", logger.ErrorField(accErr), logger.String("account_id", inv.AccountID))
				return
			}
			acct, _ := res.(account.ProjectBillingAccount)
			if acct.Email == "" {
				logger.LogError("dunning.worker.account_no_email", logger.String("account_id", inv.AccountID))
				return
			}
			logger.LogInfo("dunning.worker.retrying_payment", logger.String("invoice_id", inv.ID), logger.String("account_id", inv.AccountID))
			failedPayment := &payment.FailedPayment{ID: inv.ID, InvoiceID: inv.ID, DunningAttempts: inv.DunningAttempts, DunningState: inv.DunningStatus, LastDunningAttempt: inv.DunningNextAttemptAt}
			result, payErr := payment.RetryPayment(c.Context(), h.PaymentStore, failedPayment)
			if payErr == nil && result != nil && result.Status == "succeeded" {
				err := h.Store.UpdateInvoiceStatus(c.Context(), inv.ID, "paid")
				if err != nil {
					logger.LogError("dunning.worker.update_invoice_status_failed",
						logger.ErrorField(err),
						logger.String("invoice_id", inv.ID))
				}
				details := map[string]interface{}{
					"invoice_id":    inv.ID,
					"amount":        inv.Amount,
					"currency":      inv.Currency,
					"due_date":      inv.DueDate,
					"status":        "paid",
					"account_id":    acct.ID,
					"account_email": acct.Email,
					"tenant_id":     acct.TenantID,
				}
				nErr := h.Notify.SendNotification(
					context.Background(),
					acct.TenantID,
					security_management.NotificationEmail,
					[]string{acct.Email},
					"invoice.issued",
					details,
					3,
				)
				if nErr != nil {
					logger.LogError("dunning.worker.notify_paid_failed", logger.ErrorField(nErr), logger.String("account_id", acct.ID))
				}
				logger.LogInfo("dunning.worker.payment_success",
					logger.String("invoice_id", inv.ID),
					logger.String("tenant_id", acct.TenantID),
					logger.Int("attempts", inv.DunningAttempts+1))

			}
			logger.LogError("dunning.worker.payment_retry_failed", logger.ErrorField(payErr), logger.String("invoice_id", inv.ID))
			details := map[string]interface{}{
				"invoice_id":    inv.ID,
				"amount":        inv.Amount,
				"currency":      inv.Currency,
				"status":        "payment_failed",
				"account_id":    acct.ID,
				"account_email": acct.Email,
			}
			nErr := h.Notify.SendNotification(
				context.Background(),
				acct.TenantID,
				security_management.NotificationEmail,
				[]string{acct.Email},
				"invoice.payment_failed",
				details,
				3,
			)
			if nErr != nil {
				logger.LogError("dunning.worker.notify_failed_failed", logger.ErrorField(nErr), logger.String("account_id", acct.ID))
			}
			// Optionally: escalate after N failures, e.g. mark as "collections" or similar
		}(invoice)
	}
	return c.Status(fiber.StatusCreated).JSON(invoice)
}

func (h *BillingAdminHandler) UpdateInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateInvoice: missing invoice ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateInvoice: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "Invalid invoice data"})
	}
	invoice, err := h.InvoiceService.UpdateInvoice(input)
	if err != nil {
		logger.LogError("UpdateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update invoice"})
	}
	return c.JSON(invoice)
}

func (h *BillingAdminHandler) GetInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetInvoice: missing invoice ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	invoice, err := h.InvoiceService.GetInvoice(id)
	if err != nil {
		logger.LogError("GetInvoice: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Invoice not found"})
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
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"invoices": invoices, "page": page, "page_size": pageSize})
}

// --- ExchangeRate Handlers ---

func (h *BillingAdminHandler) CreateExchangeRate(c *fiber.Ctx) error {
	var input ExchangeRate
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" || input.Rate <= 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency, quote_currency, and positive rate required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	input.UpdatedAt = time.Now().UTC()
	if input.ID == "" {
		input.ID = commonutil.GenerateUUID()
	}
	rate, err := h.Store.CreateExchangeRate(c.Context(), input)
	if err != nil {
		logger.LogError("CreateExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	return c.Status(fiber.StatusCreated).JSON(rate)
}

func (h *BillingAdminHandler) UpdateExchangeRate(c *fiber.Ctx) error {
	var input ExchangeRate
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" || input.Rate <= 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency, quote_currency, and positive rate required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	input.UpdatedAt = time.Now().UTC()
	rate, err := h.Store.UpdateExchangeRate(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	return c.JSON(rate)
}

func (h *BillingAdminHandler) DeleteExchangeRate(c *fiber.Ctx) error {
	var input struct {
		BaseCurrency  string `json:"base_currency"`
		QuoteCurrency string `json:"quote_currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("DeleteExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency and quote_currency required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	err := h.Store.DeleteExchangeRate(c.Context(), input.BaseCurrency, input.QuoteCurrency)
	if err != nil {
		logger.LogError("DeleteExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrExpectationFailed)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *BillingAdminHandler) GetExchangeRate(c *fiber.Ctx) error {
	var input struct {
		BaseCurrency  string `json:"base_currency"`
		QuoteCurrency string `json:"quote_currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("GetExchangeRate: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.BaseCurrency == "" || input.QuoteCurrency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "base_currency and quote_currency required"})
	}
	if len(input.BaseCurrency) != 3 || len(input.QuoteCurrency) != 3 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "currencies must be ISO 4217 codes"})
	}
	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)
	input.QuoteCurrency = strings.ToUpper(input.QuoteCurrency)
	rate, err := h.Store.GetExchangeRate(c.Context(), input.BaseCurrency, input.QuoteCurrency)
	if err != nil {
		logger.LogError("GetExchangeRate: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(rate)
}

func (h *BillingAdminHandler) ListExchangeRates(c *fiber.Ctx) error {
	rates, err := h.Store.ListExchangeRates(c.Context())
	if err != nil {
		logger.LogError("ListExchangeRates: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"exchange_rates": rates})
}

// --- TenantCurrency Handlers ---

func (h *BillingAdminHandler) SetTenantCurrency(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("SetTenantCurrency: tenant_id required", logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	currency := c.Query("currency")
	if currency == "" {
		logger.LogError("SetTenantCurrency: currency required", logger.String("currency", currency))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "currency required"})
	}
	curr, err := h.Store.SetTenantCurrency(c.Context(), tenantID, currency)
	if err != nil {
		logger.LogError("SetTenantCurrency: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("currency", currency))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(curr)
}

func (h *BillingAdminHandler) GetTenantCurrency(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTenantCurrency: tenant_id required", logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	curr, err := h.Store.GetTenantCurrency(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetTenantCurrency: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(curr)
}

// UpdateExchangeRatesFromExternal updates exchange rates from an external API service
func (h *BillingAdminHandler) UpdateExchangeRatesFromExternal(c *fiber.Ctx) error {
	var input struct {
		Source       string   `json:"source"`        // "ecb", "fixer", etc.
		BaseCurrency string   `json:"base_currency"` // Base currency for all rates
		Currencies   []string `json:"currencies"`    // List of currencies to update against base
		APIKey       string   `json:"api_key"`       // Optional API key for some services
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateExchangeRatesFromExternal: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	// Validate inputs
	if input.Source == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "source is required"})
	}

	if input.BaseCurrency == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "base_currency is required"})
	}

	if len(input.BaseCurrency) != 3 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "base_currency must be ISO 4217 code"})
	}

	input.BaseCurrency = strings.ToUpper(input.BaseCurrency)

	// If no currencies specified, use some common ones
	if len(input.Currencies) == 0 {
		input.Currencies = []string{"USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF"}
	}

	// Validate all currency codes
	for i, currency := range input.Currencies {
		if len(currency) != 3 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("currency at index %d must be ISO 4217 code", i),
			})
		}
		input.Currencies[i] = strings.ToUpper(currency)
	}

	// URLs for different external rate providers
	var ratesURL string
	var client = http.Client{
		Timeout: 10 * time.Second,
	}

	switch strings.ToLower(input.Source) {
	case "ecb":
		// European Central Bank (free, no API key)
		ratesURL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
	case "fixer":
		// Fixer.io (requires API key)
		if input.APIKey == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "api_key is required for fixer"})
		}
		ratesURL = fmt.Sprintf("http://data.fixer.io/api/latest?access_key=%s&base=%s", input.APIKey, input.BaseCurrency)
	case "openexchangerates":
		// Open Exchange Rates (requires API key)
		if input.APIKey == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "api_key is required for openexchangerates"})
		}
		ratesURL = fmt.Sprintf("https://openexchangerates.org/api/latest.json?app_id=%s&base=%s", input.APIKey, input.BaseCurrency)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported source"})
	}

	// Make HTTP request to get exchange rates
	req, err := http.NewRequestWithContext(c.Context(), "GET", ratesURL, nil)
	if err != nil {
		logger.LogError("UpdateExchangeRatesFromExternal: request creation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create request"})
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("UpdateExchangeRatesFromExternal: request failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch exchange rates"})
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.LogError("UpdateExchangeRatesFromExternal: API returned error",
			logger.Int("status_code", resp.StatusCode))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("exchange rate API returned status code %d", resp.StatusCode),
		})
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("UpdateExchangeRatesFromExternal: failed to read response body", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read response"})
	}

	// Parse response based on source
	rates := make(map[string]float64)

	switch strings.ToLower(input.Source) {
	case "ecb":
		// Parse XML from ECB
		var ecbData struct {
			Cube struct {
				Cube struct {
					Cube []struct {
						Currency string  `xml:"currency,attr"`
						Rate     float64 `xml:"rate,attr"`
					} `xml:"Cube"`
				} `xml:"Cube"`
			} `xml:"Cube"`
		}
		if err := xml.Unmarshal(body, &ecbData); err != nil {
			logger.LogError("UpdateExchangeRatesFromExternal: failed to parse ECB XML", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse ECB response"})
		}

		for _, cube := range ecbData.Cube.Cube.Cube {
			rates[cube.Currency] = cube.Rate
		}

		// ECB uses EUR as base, so we need to handle conversions if input.BaseCurrency is not EUR
		if input.BaseCurrency != "EUR" {
			// Check if we have a rate for the requested base currency
			baseRate, ok := rates[input.BaseCurrency]
			if !ok {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": fmt.Sprintf("base currency %s not found in ECB rates", input.BaseCurrency),
				})
			}

			// Adjust all rates to the new base
			for curr, rate := range rates {
				rates[curr] = rate / baseRate
			}
			// Add EUR rate
			rates["EUR"] = 1.0 / baseRate
		}

	case "fixer", "openexchangerates":
		// Parse JSON from Fixer or Open Exchange Rates
		var data struct {
			Success bool               `json:"success"`
			Base    string             `json:"base"`
			Rates   map[string]float64 `json:"rates"`
			Error   struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			logger.LogError("UpdateExchangeRatesFromExternal: failed to parse JSON response", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse response"})
		}

		// Check for API-specific errors
		if !data.Success {
			logger.LogError("UpdateExchangeRatesFromExternal: API returned error response",
				logger.String("error_code", data.Error.Code),
				logger.String("error_message", data.Error.Message))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Exchange rate API returned an error, please check API credentials",
			})
		}

		rates = data.Rates
	}

	// Store rates in database
	results := make([]ExchangeRate, 0, len(input.Currencies))

	for _, currency := range input.Currencies {
		if currency == input.BaseCurrency {
			// Skip base currency against itself
			continue
		}

		rate, ok := rates[currency]
		if !ok {
			logger.LogWarn("UpdateExchangeRatesFromExternal: currency not found in response",
				logger.String("currency", currency))
			continue
		}

		// Create exchange rate record
		exchangeRate := ExchangeRate{
			ID:            commonutil.GenerateUUID(),
			BaseCurrency:  input.BaseCurrency,
			QuoteCurrency: currency,
			Rate:          rate,
			Source:        input.Source,
			UpdatedAt:     time.Now().UTC(),
		}

		// Store in database
		storedRate, err := h.Store.CreateExchangeRate(c.Context(), exchangeRate)
		if err != nil {
			logger.LogError("UpdateExchangeRatesFromExternal: failed to store rate",
				logger.ErrorField(err),
				logger.String("base", exchangeRate.BaseCurrency),
				logger.String("quote", exchangeRate.QuoteCurrency))
			continue
		}

		results = append(results, storedRate)
	}

	if len(results) == 0 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update any exchange rates"})
	}

	return c.JSON(fiber.Map{
		"updated_rates":   results,
		"source":          input.Source,
		"base_currency":   input.BaseCurrency,
		"updated_count":   len(results),
		"requested_count": len(input.Currencies),
	})
}

func generateInvoicePDF(pdfData map[string]interface{}) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	if title, ok := pdfData["title"].(string); ok && title != "" {
		pdf.SetTitle(title, false)
	}

	// Set up document properties
	pdf.SetAuthor("SubInc Billing System", false)
	pdf.SetCreator("SubInc", false)

	// Add page
	pdf.AddPage()

	// Set up default margins
	const marginLeft = 10
	const marginTop = 10

	// Company logo and branding
	if logo, ok := pdfData["logo"].(string); ok && logo != "" {
		pdf.ImageOptions(logo, marginLeft, marginTop, 30, 0, false, gofpdf.ImageOptions{}, 0, "")
	} else {
		// No logo provided, use text header instead
		pdf.SetFont("Arial", "B", 24)
		pdf.SetTextColor(50, 50, 150)
		pdf.Text(marginLeft, marginTop+10, "SubInc")
		pdf.SetFont("Arial", "I", 10)
		pdf.SetTextColor(100, 100, 100)
		pdf.Text(marginLeft, marginTop+16, "Billing Management System")
		pdf.SetTextColor(0, 0, 0) // Reset to black
	}

	// Top-right corner: Invoice title and number
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(50, 50, 50)
	pdf.SetXY(120, marginTop)
	pdf.Cell(80, 10, "INVOICE")
	if invoiceNum, ok := pdfData["invoice_number"].(string); ok && invoiceNum != "" {
		pdf.SetXY(120, marginTop+10)
		pdf.SetFont("Arial", "", 12)
		pdf.Cell(80, 10, "# "+invoiceNum)
	}
	pdf.SetTextColor(0, 0, 0) // Reset to black

	// Draw a line to separate header
	pdf.Line(marginLeft, marginTop+25, 200, marginTop+25)

	// Date and billing information section
	pdf.SetXY(marginLeft, marginTop+30)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(40, 6, "Invoice Date:")
	pdf.SetXY(marginLeft+40, marginTop+30)
	pdf.SetFont("Arial", "", 11)
	if date, ok := pdfData["invoice_date"].(string); ok && date != "" {
		pdf.Cell(60, 6, date)
	}

	pdf.SetXY(marginLeft, marginTop+36)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(40, 6, "Due Date:")
	pdf.SetXY(marginLeft+40, marginTop+36)
	pdf.SetFont("Arial", "", 11)
	if dueDate, ok := pdfData["due_date"].(string); ok && dueDate != "" {
		pdf.Cell(60, 6, dueDate)
	}

	pdf.SetXY(marginLeft, marginTop+42)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(40, 6, "Invoice Status:")
	pdf.SetXY(marginLeft+40, marginTop+42)
	pdf.SetFont("Arial", "", 11)
	if status, ok := pdfData["status"].(string); ok && status != "" {
		pdf.Cell(60, 6, status)
	}

	// Account information
	pdf.SetXY(120, marginTop+30)
	pdf.SetFont("Arial", "B", 11)
	pdf.Cell(40, 6, "Bill To:")
	pdf.SetXY(120, marginTop+36)
	pdf.SetFont("Arial", "", 11)
	if accountEmail, ok := pdfData["account_email"].(string); ok && accountEmail != "" {
		pdf.Cell(80, 6, accountEmail)
	}
	pdf.SetXY(120, marginTop+42)
	if accountID, ok := pdfData["account_id"].(string); ok && accountID != "" {
		pdf.Cell(80, 6, "Account: "+accountID)
	}

	// Draw a line to separate billing info from items
	pdf.Line(marginLeft, marginTop+50, 200, marginTop+50)

	// Invoice line items (if provided)
	if lineItems, ok := pdfData["line_items"].([]map[string]string); ok && len(lineItems) > 0 {
		// Table header
		pdf.SetXY(marginLeft, marginTop+55)
		pdf.SetFont("Arial", "B", 11)
		pdf.SetFillColor(240, 240, 240)

		// Draw table header - gofpdf method signature is different than what we tried
		pdf.CellFormat(100, 8, "Description", "1", 0, "", true, 0, "")
		pdf.CellFormat(30, 8, "Quantity", "1", 0, "C", true, 0, "")
		pdf.CellFormat(30, 8, "Unit Price", "1", 0, "R", true, 0, "")
		pdf.CellFormat(30, 8, "Amount", "1", 0, "R", true, 0, "")

		// Table items
		yPos := float64(marginTop + 63)
		pdf.SetFont("Arial", "", 10)
		for _, item := range lineItems {
			pdf.SetXY(marginLeft, yPos)
			pdf.CellFormat(100, 6, item["description"], "1", 0, "", false, 0, "")
			pdf.CellFormat(30, 6, item["quantity"], "1", 0, "C", false, 0, "")
			pdf.CellFormat(30, 6, item["unit_price"], "1", 0, "R", false, 0, "")
			pdf.CellFormat(30, 6, item["amount"], "1", 0, "R", false, 0, "")
			yPos += 6
		}
	} else {
		// Summary table
		if table, ok := pdfData["table"].([][3]string); ok && len(table) > 0 {
			// Table header
			pdf.SetXY(marginLeft, marginTop+55)
			pdf.SetFont("Arial", "B", 11)
			pdf.SetFillColor(240, 240, 240)

			// Draw table header - use CellFormat instead of Cell
			pdf.CellFormat(130, 8, "Description", "1", 0, "", true, 0, "")
			pdf.CellFormat(30, 8, "Amount", "1", 0, "R", true, 0, "")
			pdf.CellFormat(30, 8, "Currency", "1", 0, "C", true, 0, "")

			// Table items
			yPos := float64(marginTop + 63)
			pdf.SetFont("Arial", "", 10)
			for _, row := range table {
				pdf.SetXY(marginLeft, yPos)
				pdf.CellFormat(130, 6, row[0], "1", 0, "", false, 0, "")
				pdf.CellFormat(30, 6, row[1], "1", 0, "R", false, 0, "")
				pdf.CellFormat(30, 6, row[2], "1", 0, "C", false, 0, "")
				yPos += 6
			}
		}
	}

	// Footer/terms
	if footer, ok := pdfData["footer"].(string); ok && footer != "" {
		pdf.SetY(-40) // Position at 40mm from bottom
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(0, 5, footer, "", "L", false)
	}

	// Company details at the very bottom
	pdf.SetFont("Arial", "", 8)
	pdf.SetY(-25)
	if company, ok := pdfData["company_name"].(string); ok && company != "" {
		pdf.MultiCell(0, 4, company, "", "C", false)
	} else {
		pdf.MultiCell(0, 4, "SubInc - Multi-tenant SaaS Billing Management", "", "C", false)
	}

	pdf.SetY(-20)
	if contactInfo, ok := pdfData["contact_info"].(string); ok && contactInfo != "" {
		pdf.MultiCell(0, 4, contactInfo, "", "C", false)
	} else {
		pdf.MultiCell(0, 4, "support@subinc.example.com | www.subinc-example.com", "", "C", false)
	}

	// Page numbering
	pdf.SetY(-15)
	pdf.SetFont("Arial", "I", 8)
	pdf.CellFormat(0, 10, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")

	// Output to buffer
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DownloadInvoicePDF returns the invoice PDF as an attachment.
// Supports all invoice types and includes comprehensive details.
func (h *BillingAdminHandler) DownloadInvoicePDF(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DownloadInvoicePDF: missing invoice ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "error occured",
		})
	}

	// Get the invoice PDF data
	pdfData, err := h.InvoiceExportService.DownloadInvoicePDF(c.Context(), id)
	if err != nil {
		logger.LogError("DownloadInvoicePDF: failed to generate PDF", logger.ErrorField(err), logger.String("invoice_id", id))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate invoice PDF. Please try again later.",
		})
	}

	// Set appropriate headers and return the PDF data
	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=invoice-%s.pdf", id))
	return c.Send(pdfData)
}

func (h *BillingAdminHandler) StripeWebhookHandler(c *fiber.Ctx) error {
	const maxBodyBytes = int64(65536)
	body := c.BodyRaw()
	if int64(len(body)) > maxBodyBytes {
		logger.LogError("stripe.webhook.body_too_large")
		return c.SendStatus(fiber.StatusOK)
	}

	// Get webhook secret from environment or configuration
	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if secret == "" {
		// Just use the environment variable for now
		logger.LogError("stripe.webhook.secret_missing")
		return c.SendStatus(fiber.StatusOK)
	}

	// Verify Stripe signature
	sig := c.Get("Stripe-Signature")
	if sig == "" {
		logger.LogError("stripe.webhook.signature_missing")
		return c.SendStatus(fiber.StatusOK)
	}

	// Construct the event
	event, err := webhook.ConstructEvent(body, sig, secret)
	if err != nil {
		logger.LogError("stripe.webhook.invalid_signature",
			logger.ErrorField(err),
			logger.String("signature", sig))
		return c.SendStatus(fiber.StatusOK)
	}

	// Check for duplicate events (idempotency)
	processed, err := h.Store.IsStripeEventProcessed(c.Context(), event.ID)
	if err != nil {
		logger.LogError("stripe.webhook.idempotency_check_failed",
			logger.ErrorField(err),
			logger.String("event_id", event.ID))
		// Continue processing even if the check fails
	} else if processed {
		logger.LogInfo("stripe.webhook.duplicate_event",
			logger.String("event_id", event.ID),
			logger.String("type", string(event.Type)))
		return c.SendStatus(fiber.StatusOK)
	}

	logger.LogInfo("stripe.webhook.event_received",
		logger.String("event_id", event.ID),
		logger.String("type", string(event.Type)))

	// Process the event based on its type
	processed = true // Assume we'll mark it as processed

	switch event.Type {
	// Invoice events
	case "invoice.paid":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_paid.missing_id")
			processed = false
			break
		}
		err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "paid")
		if err != nil {
			logger.LogError("stripe.webhook.invoice_paid.update_failed",
				logger.ErrorField(err),
				logger.String("invoice_id", invoiceID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.invoice_paid.updated",
				logger.String("invoice_id", invoiceID))

			// Just log that the invoice is paid - payments will be updated separately
			logger.LogInfo("stripe.webhook.invoice_paid.payments_update",
				logger.String("invoice_id", invoiceID))
		}

	// Payment intent events
	case "payment_intent.succeeded":
		intentObj := event.Data.Object
		paymentIntentID, ok := intentObj["id"].(string)
		if !ok || paymentIntentID == "" {
			logger.LogError("stripe.webhook.payment_intent_succeeded.missing_id")
			processed = false
			break
		}

		// Update payment status directly
		if err := h.PaymentStore.UpdatePaymentStatus(c.Context(), paymentIntentID, "succeeded"); err != nil {
			logger.LogError("stripe.webhook.payment_intent_succeeded.update_status_failed",
				logger.ErrorField(err),
				logger.String("payment_id", paymentIntentID))
		}

		// If attached to an invoice, update the invoice too
		invoiceID, ok := intentObj["invoice"].(string)
		if ok && invoiceID != "" {
			err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "paid")
			if err != nil {
				logger.LogError("stripe.webhook.payment_intent_succeeded.update_invoice_failed",
					logger.ErrorField(err),
					logger.String("invoice_id", invoiceID))
				processed = false
			} else {
				logger.LogInfo("stripe.webhook.payment_intent_succeeded.updated",
					logger.String("payment_id", paymentIntentID),
					logger.String("invoice_id", invoiceID))
			}
		} else {
			logger.LogInfo("stripe.webhook.payment_intent_succeeded.standalone",
				logger.String("payment_id", paymentIntentID))
		}

	case "payment_intent.payment_failed":
		intentObj := event.Data.Object
		paymentIntentID, ok := intentObj["id"].(string)
		if !ok || paymentIntentID == "" {
			logger.LogError("stripe.webhook.payment_intent_failed.missing_id")
			processed = false
			break
		}

		// Update payment status directly
		if err := h.PaymentStore.UpdatePaymentStatus(c.Context(), paymentIntentID, "failed"); err != nil {
			logger.LogError("stripe.webhook.payment_intent_failed.update_status_failed",
				logger.ErrorField(err),
				logger.String("payment_id", paymentIntentID))
		}

		// If attached to an invoice, update the invoice too
		invoiceID, ok := intentObj["invoice"].(string)
		if ok && invoiceID != "" {
			err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "payment_failed")
			if err != nil {
				logger.LogError("stripe.webhook.payment_intent_failed.update_invoice_failed",
					logger.ErrorField(err),
					logger.String("invoice_id", invoiceID))
				processed = false
			} else {
				logger.LogInfo("stripe.webhook.payment_intent_failed.updated",
					logger.String("payment_id", paymentIntentID),
					logger.String("invoice_id", invoiceID))
			}
		} else {
			logger.LogInfo("stripe.webhook.payment_intent_failed.standalone",
				logger.String("payment_id", paymentIntentID))
		}

	case "invoice.payment_failed":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_payment_failed.missing_id")
			processed = false
			break
		}
		err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "payment_failed")
		if err != nil {
			logger.LogError("stripe.webhook.invoice_payment_failed.update_failed",
				logger.ErrorField(err),
				logger.String("invoice_id", invoiceID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.invoice_payment_failed.updated",
				logger.String("invoice_id", invoiceID))
		}

	// Subscription events
	case "customer.subscription.created":
		subObj := event.Data.Object
		subID, ok := subObj["id"].(string)
		if !ok || subID == "" {
			logger.LogError("stripe.webhook.subscription_created.missing_id")
			processed = false
			break
		}
		err := h.Store.UpdateSubscriptionStatus(c.Context(), subID, "active")
		if err != nil {
			logger.LogError("stripe.webhook.subscription_created.update_failed",
				logger.ErrorField(err),
				logger.String("subscription_id", subID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.subscription_created.updated",
				logger.String("subscription_id", subID))
		}

	case "customer.subscription.updated":
		subObj := event.Data.Object
		subID, ok := subObj["id"].(string)
		if !ok || subID == "" {
			logger.LogError("stripe.webhook.subscription_updated.missing_id")
			processed = false
			break
		}
		status, ok := subObj["status"].(string)
		if !ok || status == "" {
			logger.LogError("stripe.webhook.subscription_updated.missing_status")
			processed = false
			break
		}
		err := h.Store.UpdateSubscriptionStatus(c.Context(), subID, status)
		if err != nil {
			logger.LogError("stripe.webhook.subscription_updated.update_failed",
				logger.ErrorField(err),
				logger.String("subscription_id", subID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.subscription_updated.updated",
				logger.String("subscription_id", subID),
				logger.String("status", status))
		}

	case "customer.subscription.deleted":
		subObj := event.Data.Object
		subID, ok := subObj["id"].(string)
		if !ok || subID == "" {
			logger.LogError("stripe.webhook.subscription_deleted.missing_id")
			processed = false
			break
		}
		err := h.Store.UpdateSubscriptionStatus(c.Context(), subID, "canceled")
		if err != nil {
			logger.LogError("stripe.webhook.subscription_deleted.update_failed",
				logger.ErrorField(err),
				logger.String("subscription_id", subID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.subscription_deleted.updated",
				logger.String("subscription_id", subID))
		}

	// Other invoice status changes
	case "invoice.upcoming", "invoice.finalized", "invoice.voided", "invoice.marked_uncollectible":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_event.missing_id",
				logger.String("type", string(event.Type)))
			processed = false
			break
		}
		status := ""
		switch event.Type {
		case "invoice.upcoming":
			status = "upcoming"
		case "invoice.finalized":
			status = "finalized"
		case "invoice.voided":
			status = "voided"
		case "invoice.marked_uncollectible":
			status = "uncollectible"
		}
		if status != "" {
			err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, status)
			if err != nil {
				logger.LogError("stripe.webhook.invoice_event.update_failed",
					logger.ErrorField(err),
					logger.String("invoice_id", invoiceID),
					logger.String("status", status))
				processed = false
			} else {
				logger.LogInfo("stripe.webhook.invoice_event.updated",
					logger.String("invoice_id", invoiceID),
					logger.String("status", status))
			}
		}

	// Refund events
	case "charge.refunded":
		chargeObj := event.Data.Object
		paymentID, ok := chargeObj["payment_intent"].(string)
		if !ok || paymentID == "" {
			logger.LogError("stripe.webhook.charge_refunded.missing_payment_intent")
			processed = false
			break
		}
		err := h.PaymentStore.UpdatePaymentStatus(c.Context(), paymentID, "refunded")
		if err != nil {
			logger.LogError("stripe.webhook.charge_refunded.update_failed",
				logger.ErrorField(err),
				logger.String("payment_id", paymentID))
			processed = false
		} else {
			logger.LogInfo("stripe.webhook.charge_refunded.updated",
				logger.String("payment_id", paymentID))
		}

		// Dispute events
	case "charge.dispute.created":
		disputeObj := event.Data.Object
		disputeID, ok := disputeObj["id"].(string)
		if !ok || disputeID == "" {
			logger.LogError("stripe.webhook.dispute_created.missing_id")
			processed = false
			break
		}

		// Just log the dispute event for now
		// Implement proper dispute handling in a future update
		logger.LogInfo("stripe.webhook.dispute_created.received",
			logger.String("dispute_id", disputeID))

	default:
		logger.LogInfo("stripe.webhook.unhandled_event",
			logger.String("type", string(event.Type)))
		// We still mark it as processed so we don't keep trying to process it
	}

	// Mark the event as processed if successful
	if processed {
		if err := h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type)); err != nil {
			logger.LogError("stripe.webhook.mark_processed_failed",
				logger.ErrorField(err),
				logger.String("event_id", event.ID))
		}
	}

	// Always return 200 OK to Stripe, even if we had errors processing the event
	// This prevents Stripe from retrying events that we can't process
	return c.SendStatus(fiber.StatusOK)
}

func DunningWorker(store *PostgresStore, paymentStore payment.StoreInterface, accountService account.BillingAccountService, notificationService security_management.NotificationService) {
	ctx := context.Background()
	logger.LogInfo("dunning.worker.starting")
	for {
		// Process all tenants with active dunning configs
		tenants, err := store.ListTenantsWithDunningConfig(ctx)
		if err != nil {
			logger.LogError("dunning.worker.list_tenants_failed", logger.ErrorField(err))
			time.Sleep(5 * time.Minute)
			continue
		}

		// Process each tenant with its own dunning configuration
		for _, tenantID := range tenants {
			// Get tenant-specific dunning configuration
			dunningConfig, err := store.GetDunningConfig(ctx, tenantID)
			if err != nil || dunningConfig == nil {
				logger.LogError("dunning.worker.get_dunning_config_failed",
					logger.ErrorField(err),
					logger.String("tenant_id", tenantID))
				continue
			}

			// Get invoices eligible for dunning from this tenant
			invoices, err := store.ListInvoicesForDunning(ctx, time.Now().UTC(), dunningConfig.MaxAttempts, tenantID)
			if err != nil {
				logger.LogError("dunning.worker.list_invoices_failed",
					logger.ErrorField(err),
					logger.String("tenant_id", tenantID))
				continue
			}

			logger.LogInfo("dunning.worker.processing_tenant",
				logger.String("tenant_id", tenantID),
				logger.Int("invoices_to_process", len(invoices)))

			// Process each invoice eligible for dunning
			for _, inv := range invoices {
				// Get account details
				res, err := accountService.Get(ctx, account.AccountTypeProject, inv.AccountID)
				if err != nil {
					logger.LogError("dunning.worker.account_not_found",
						logger.ErrorField(err),
						logger.String("account_id", inv.AccountID),
						logger.String("invoice_id", inv.ID))
					continue
				}

				acct, _ := res.(account.ProjectBillingAccount)
				if acct.Email == "" {
					logger.LogError("dunning.worker.account_no_email",
						logger.String("account_id", inv.AccountID),
						logger.String("invoice_id", inv.ID))
					continue
				}

				// Create dunning event to record the attempt
				eventID := commonutil.GenerateUUID()
				event := &DunningEvent{
					ID:        eventID,
					AccountID: inv.AccountID,
					InvoiceID: inv.ID,
					EventType: "automated_retry",
					Details: map[string]interface{}{
						"attempt":      inv.DunningAttempts + 1,
						"max_attempts": dunningConfig.MaxAttempts,
						"amount":       inv.Amount,
						"currency":     inv.Currency,
					},
					CreatedAt: time.Now().UTC(),
				}

				// Store event (don't fail if this fails)
				_ = store.CreateDunningEvent(ctx, event)

				logger.LogInfo("dunning.worker.retrying_payment",
					logger.String("invoice_id", inv.ID),
					logger.String("account_id", inv.AccountID),
					logger.String("tenant_id", acct.TenantID),
					logger.Int("attempt", inv.DunningAttempts+1),
					logger.Int("max_attempts", dunningConfig.MaxAttempts))

				// Set up failed payment object for retry
				failedPayment := &payment.FailedPayment{
					ID:                 inv.ID,
					InvoiceID:          inv.ID,
					DunningAttempts:    inv.DunningAttempts,
					DunningState:       inv.DunningStatus,
					LastDunningAttempt: inv.DunningNextAttemptAt,
				}

				// Retry the payment
				result, payErr := payment.RetryPayment(ctx, paymentStore, failedPayment)

				// Handle success
				if payErr == nil && result != nil && result.Status == "succeeded" {
					// Update invoice status
					err := store.UpdateInvoiceStatus(ctx, inv.ID, "paid")
					if err != nil {
						logger.LogError("dunning.worker.update_invoice_status_failed",
							logger.ErrorField(err),
							logger.String("invoice_id", inv.ID))
					}

					// Create success event
					successEvent := &DunningEvent{
						ID:        commonutil.GenerateUUID(),
						AccountID: inv.AccountID,
						InvoiceID: inv.ID,
						EventType: "payment_success",
						Details: map[string]interface{}{
							"attempt":        inv.DunningAttempts + 1,
							"payment_id":     result.PaymentID,
							"payment_method": getPaymentMethodOrDefault(result),
							"amount":         inv.Amount,
							"currency":       inv.Currency,
						},
						CreatedAt: time.Now().UTC(),
					}
					_ = store.CreateDunningEvent(ctx, successEvent)

					// Send success notification
					details := map[string]interface{}{
						"invoice_id":      inv.ID,
						"amount":          inv.Amount,
						"currency":        inv.Currency,
						"status":          "paid",
						"account_id":      acct.ID,
						"account_email":   acct.Email,
						"payment_id":      result.PaymentID,
						"dunning_attempt": inv.DunningAttempts + 1,
					}

					nErr := notificationService.SendNotification(
						ctx,
						acct.TenantID,
						security_management.NotificationEmail,
						[]string{acct.Email},
						"invoice.paid_after_retry",
						details,
						3,
					)

					if nErr != nil {
						logger.LogError("dunning.worker.notify_paid_failed",
							logger.ErrorField(nErr),
							logger.String("account_id", acct.ID))
					}

					logger.LogInfo("dunning.worker.payment_success",
						logger.String("invoice_id", inv.ID),
						logger.String("tenant_id", acct.TenantID),
						logger.Int("attempts", inv.DunningAttempts+1))

					continue
				}

				// Handle failure - determine next steps based on attempt count
				newAttempts := inv.DunningAttempts + 1

				// Calculate next attempt time based on retry intervals
				var nextAttemptAt time.Time

				if newAttempts >= dunningConfig.MaxAttempts {
					// Mark as failed if max attempts reached
					err := store.UpdateInvoiceDunning(ctx, inv.ID, "failed", newAttempts, time.Now().UTC())
					if err != nil {
						logger.LogError("dunning.worker.update_dunning_failed",
							logger.ErrorField(err),
							logger.String("invoice_id", inv.ID))
					}

					// Create final failure event
					failEvent := &DunningEvent{
						ID:        commonutil.GenerateUUID(),
						AccountID: inv.AccountID,
						InvoiceID: inv.ID,
						EventType: "dunning_failed",
						Details: map[string]interface{}{
							"final_attempt": true,
							"max_attempts":  dunningConfig.MaxAttempts,
							"amount":        inv.Amount,
							"currency":      inv.Currency,
							"error":         "Payment processing failed",
						},
						CreatedAt: time.Now().UTC(),
					}
					_ = store.CreateDunningEvent(ctx, failEvent)

					// Send final failure notification with escalation info

					details := map[string]interface{}{
						"invoice_id":    inv.ID,
						"amount":        inv.Amount,
						"currency":      inv.Currency,
						"status":        "dunning_failed",
						"account_id":    acct.ID,
						"account_email": acct.Email,
						"final_attempt": true,
						"attempts":      newAttempts,
						"max_attempts":  dunningConfig.MaxAttempts,
					}

					// Send notification about failed dunning with escalation
					nErr := notificationService.SendNotification(
						ctx,
						acct.TenantID,
						security_management.NotificationEmail,
						[]string{acct.Email},
						"invoice.dunning_failed",
						details,
						3,
					)

					if nErr != nil {
						logger.LogError("dunning.worker.notify_final_failed",
							logger.ErrorField(nErr),
							logger.String("account_id", acct.ID))
					}

					logger.LogError("dunning.worker.dunning_failed",
						logger.String("invoice_id", inv.ID),
						logger.Int("attempts", newAttempts),
						logger.String("tenant_id", acct.TenantID))

				} else {
					// Schedule next attempt based on configured intervals
					intervalIndex := newAttempts - 1
					if intervalIndex < len(dunningConfig.RetryIntervals) {
						nextAttemptAt = time.Now().UTC().Add(dunningConfig.RetryIntervals[intervalIndex])
					} else {
						// Default to 24 hours if no specific interval is configured
						nextAttemptAt = time.Now().UTC().Add(24 * time.Hour)
					}

					// Update invoice with new dunning information
					err := store.UpdateInvoiceDunning(ctx, inv.ID, "active", newAttempts, nextAttemptAt)
					if err != nil {
						logger.LogError("dunning.worker.update_dunning_failed",
							logger.ErrorField(err),
							logger.String("invoice_id", inv.ID))
					}

					// Create retry failure event
					failEvent := &DunningEvent{
						ID:        commonutil.GenerateUUID(),
						AccountID: inv.AccountID,
						InvoiceID: inv.ID,
						EventType: "payment_retry_failed",
						Details: map[string]interface{}{
							"attempt":         newAttempts,
							"max_attempts":    dunningConfig.MaxAttempts,
							"next_attempt_at": nextAttemptAt,
							"amount":          inv.Amount,
							"currency":        inv.Currency,
							"error":           "Payment processing failed",
						},
						CreatedAt: time.Now().UTC(),
					}
					_ = store.CreateDunningEvent(ctx, failEvent)

					// Send failure notification with next attempt info
					details := map[string]interface{}{
						"invoice_id":      inv.ID,
						"amount":          inv.Amount,
						"currency":        inv.Currency,
						"status":          "payment_failed",
						"account_id":      acct.ID,
						"account_email":   acct.Email,
						"attempt":         newAttempts,
						"max_attempts":    dunningConfig.MaxAttempts,
						"next_attempt_at": nextAttemptAt.Format(time.RFC3339),
					}

					nErr := notificationService.SendNotification(
						ctx,
						acct.TenantID,
						security_management.NotificationEmail,
						[]string{acct.Email},
						"invoice.payment_retry_failed",
						details,
						3,
					)

					if nErr != nil {
						logger.LogError("dunning.worker.notify_failed_failed",
							logger.ErrorField(nErr),
							logger.String("account_id", acct.ID))
					}

					logger.LogError("dunning.worker.payment_retry_failed",
						logger.ErrorField(payErr),
						logger.String("invoice_id", inv.ID),
						logger.Int("attempt", newAttempts),
						logger.String("next_attempt", nextAttemptAt.Format(time.RFC3339)))
				}
			}
		}

		// Sleep before next cycle - check every 15 minutes
		time.Sleep(15 * time.Minute)
	}
}

func (h *BillingAdminHandler) DeleteInvoice(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteInvoice: missing invoice ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	err := h.InvoiceService.DeleteInvoice(id)
	if err != nil {
		logger.LogError("DeleteInvoice: failed", logger.ErrorField(err), logger.String("id", id))
		// Check if this is a "not found" error, but without exposing internal error details
		if strings.Contains(err.Error(), "no rows") || strings.Contains(err.Error(), "not found") {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Invoice not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete invoice"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListInvoicePlugins returns a list of registered invoice plugins
func (h *BillingAdminHandler) ListInvoicePlugins(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginNames := h.PluginManager.ListPlugins("invoice")
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// RegisterInvoicePlugin registers a new invoice plugin
func (h *BillingAdminHandler) RegisterInvoicePlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Plugins are registered via code, this endpoint just enables/configures them
	plugin, exists := h.PluginManager.GetPlugin("invoice", pluginName)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Invoice plugin '%s' not found", pluginName),
		})
	}

	// Type assert to the invoice plugin interface
	invoicePlugin, ok := plugin.(InvoicePlugin)
	if !ok {
		h.Logger.Error(fmt.Sprintf("Plugin %s is not a valid invoice plugin", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid plugin type",
		})
	}

	if err := invoicePlugin.Initialize(config); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to initialize invoice plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initialize plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Invoice plugin '%s' registered and initialized", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Invoice plugin '%s' registered successfully", pluginName),
	})
}

// UnregisterInvoicePlugin unregisters an invoice plugin
func (h *BillingAdminHandler) UnregisterInvoicePlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	if err := h.PluginManager.UnregisterPlugin("invoice", pluginName); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to unregister invoice plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to unregister plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Invoice plugin '%s' unregistered", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Invoice plugin '%s' unregistered successfully", pluginName),
	})
}

// ListPaymentPlugins returns a list of registered payment plugins
func (h *BillingAdminHandler) ListPaymentPlugins(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginNames := h.PluginManager.ListPlugins("payment")
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// RegisterPaymentPlugin registers a new payment plugin
func (h *BillingAdminHandler) RegisterPaymentPlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Plugins are registered via code, this endpoint just enables/configures them
	plugin, exists := h.PluginManager.GetPlugin("payment", pluginName)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Payment plugin '%s' not found", pluginName),
		})
	}

	// Type assert to the payment plugin interface
	paymentPlugin, ok := plugin.(payment.PaymentPlugin)
	if !ok {
		h.Logger.Error(fmt.Sprintf("Plugin %s is not a valid payment plugin", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid plugin type",
		})
	}

	if err := paymentPlugin.Initialize(config); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to initialize payment plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initialize plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Payment plugin '%s' registered and initialized", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Payment plugin '%s' registered successfully", pluginName),
	})
}

// UnregisterPaymentPlugin unregisters a payment plugin
func (h *BillingAdminHandler) UnregisterPaymentPlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	if err := h.PluginManager.UnregisterPlugin("payment", pluginName); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to unregister payment plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to unregister plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Payment plugin '%s' unregistered", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Payment plugin '%s' unregistered successfully", pluginName),
	})
}

// ListTaxPlugins returns a list of registered tax plugins
func (h *BillingAdminHandler) ListTaxPlugins(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginNames := h.PluginManager.ListPlugins("tax")
	return c.JSON(fiber.Map{"plugins": pluginNames})
}

// RegisterTaxPlugin registers a new tax plugin
func (h *BillingAdminHandler) RegisterTaxPlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Plugins are registered via code, this endpoint just enables/configures them
	plugin, exists := h.PluginManager.GetPlugin("tax", pluginName)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Tax plugin '%s' not found", pluginName),
		})
	}

	// Type assert to the tax plugin interface
	taxPlugin, ok := plugin.(tax.TaxPlugin)
	if !ok {
		h.Logger.Error(fmt.Sprintf("Plugin %s is not a valid tax plugin", pluginName))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid plugin type",
		})
	}

	if err := taxPlugin.Initialize(config); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to initialize tax plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to initialize plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Tax plugin '%s' registered and initialized", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Tax plugin '%s' registered successfully", pluginName),
	})
}

// UnregisterTaxPlugin unregisters a tax plugin
func (h *BillingAdminHandler) UnregisterTaxPlugin(c *fiber.Ctx) error {
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Plugin manager not initialized",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	if err := h.PluginManager.UnregisterPlugin("tax", pluginName); err != nil {
		h.Logger.Error(fmt.Sprintf("Failed to unregister tax plugin %s: %v", pluginName, err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to unregister plugin",
		})
	}

	h.Logger.Info(fmt.Sprintf("Tax plugin '%s' unregistered", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Tax plugin '%s' unregistered successfully", pluginName),
	})
}

// Unified plugin management handlers
func (h *BillingAdminHandler) ListPlugins(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	if pluginType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin type is required"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}
	plugins := h.PluginManager.ListPlugins(pluginType)
	return c.JSON(fiber.Map{"plugins": plugins})
}

func (h *BillingAdminHandler) GetPlugin(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	pluginName := c.Params("name")
	if pluginType == "" || pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin type and name are required"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}

	// Use the generic plugin lookup for all types
	plugin, found := h.PluginManager.GetPlugin(pluginType, pluginName)
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
	}

	// Use reflection to get plugin info
	pluginValue := reflect.ValueOf(plugin)

	// Get name
	var name string
	if nameMethod := pluginValue.MethodByName("Name"); nameMethod.IsValid() {
		nameResult := nameMethod.Call([]reflect.Value{})
		if len(nameResult) > 0 {
			name = nameResult[0].String()
		}
	}

	// Get version
	var version string
	if versionMethod := pluginValue.MethodByName("Version"); versionMethod.IsValid() {
		versionResult := versionMethod.Call([]reflect.Value{})
		if len(versionResult) > 0 {
			version = versionResult[0].String()
		}
	}

	// Get capabilities
	var capabilities []string
	if capabilitiesMethod := pluginValue.MethodByName("Capabilities"); capabilitiesMethod.IsValid() {
		capabilitiesResult := capabilitiesMethod.Call([]reflect.Value{})
		if len(capabilitiesResult) > 0 && !capabilitiesResult[0].IsNil() {
			capabilitiesValue := capabilitiesResult[0]
			if capabilitiesValue.Kind() == reflect.Slice {
				capabilities = make([]string, capabilitiesValue.Len())
				for i := 0; i < capabilitiesValue.Len(); i++ {
					capabilities[i] = capabilitiesValue.Index(i).String()
				}
			}
		}
	}

	return c.JSON(fiber.Map{
		"name":         name,
		"version":      version,
		"capabilities": capabilities,
		"type":         pluginType,
	})
}

func (h *BillingAdminHandler) RegisterPlugin(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	pluginName := c.Params("name")
	if pluginType == "" || pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin type and name are required"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("RegisterPlugin: invalid config", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid configuration format"})
	}

	// Use the generic plugin lookup for all types
	plugin, found := h.PluginManager.GetPlugin(pluginType, pluginName)
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
	}

	// Initialize the plugin with the provided configuration
	pluginValue := reflect.ValueOf(plugin)
	if initializeMethod := pluginValue.MethodByName("Initialize"); initializeMethod.IsValid() {
		result := initializeMethod.Call([]reflect.Value{reflect.ValueOf(config)})
		if len(result) > 0 && !result[0].IsNil() {
			err := result[0].Interface().(error)
			logger.LogError("RegisterPlugin: failed to initialize plugin",
				logger.String("type", pluginType),
				logger.String("plugin", pluginName),
				logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to initialize plugin: "})
		}
	} else {
		logger.LogError("RegisterPlugin: plugin does not support initialization",
			logger.String("type", pluginType),
			logger.String("plugin", pluginName))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin does not support initialization"})
	}

	logger.LogInfo("RegisterPlugin: plugin registered and initialized", logger.String("type", pluginType), logger.String("plugin", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "plugin registered and initialized"})
}

func (h *BillingAdminHandler) UnregisterPlugin(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	pluginName := c.Params("name")
	if pluginType == "" || pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin type and name are required"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}
	if err := h.PluginManager.UnregisterPlugin(pluginType, pluginName); err != nil {
		logger.LogError("UnregisterPlugin: failed", logger.String("type", pluginType), logger.String("plugin", pluginName), logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to unregister plugin"})
	}
	logger.LogInfo("UnregisterPlugin: plugin unregistered", logger.String("type", pluginType), logger.String("plugin", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "plugin unregistered"})
}

func (h *BillingAdminHandler) DisablePlugin(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	pluginName := c.Params("name")
	tenantID := c.Query("tenant_id")
	if pluginType == "" || pluginName == "" || tenantID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "error occured"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}

	var err error
	switch pluginType {
	case "invoice":
		err = h.Store.DisableInvoicePluginConfig(c.Context(), tenantID, pluginName)
	case "payment":
		err = h.PaymentStore.DisablePaymentPlugin(c.Context(), tenantID, pluginName)
	case "tax":
		err = h.Store.DisableTaxPluginConfig(c.Context(), tenantID, pluginName)
	case "subscription", "fee", "account":
		// Get the plugin from plugin manager
		plugin, found := h.PluginManager.GetPlugin(pluginType, pluginName)
		if !found {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
		}

		// Use reflection to check if the plugin supports the Disable method
		if disableMethod := reflect.ValueOf(plugin).MethodByName("Disable"); disableMethod.IsValid() {
			result := disableMethod.Call([]reflect.Value{reflect.ValueOf(c.Context()), reflect.ValueOf(tenantID)})
			if len(result) > 0 && !result[0].IsNil() {
				err = result[0].Interface().(error)
			}
		} else {
			err = fmt.Errorf("plugin does not support disable operation")
		}
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported plugin type"})
	}

	if err != nil {
		logger.LogError("DisablePlugin: failed", logger.String("type", pluginType), logger.String("plugin", pluginName), logger.String("tenant_id", tenantID), logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "failed to disable plugin"})
	}

	logger.LogInfo("DisablePlugin: plugin disabled", logger.String("type", pluginType), logger.String("plugin", pluginName), logger.String("tenant_id", tenantID))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "plugin disabled"})
}

func (h *BillingAdminHandler) ConfigurePlugin(c *fiber.Ctx) error {
	pluginType := c.Params("type")
	pluginName := c.Params("name")
	if pluginType == "" || pluginName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin type and name are required"})
	}
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("ConfigurePlugin: invalid config", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid configuration format"})
	}
	if h.PluginManager == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "plugin manager not initialized"})
	}

	// Use the generic plugin lookup for all types
	plugin, found := h.PluginManager.GetPlugin(pluginType, pluginName)
	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
	}

	// Use reflection to call Initialize method
	if initializeMethod := reflect.ValueOf(plugin).MethodByName("Initialize"); initializeMethod.IsValid() {
		result := initializeMethod.Call([]reflect.Value{reflect.ValueOf(config)})
		if len(result) > 0 && !result[0].IsNil() {
			err := result[0].Interface().(error)
			logger.LogError("ConfigurePlugin: failed to configure plugin",
				logger.String("type", pluginType),
				logger.String("plugin", pluginName),
				logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to configure plugin"})
		}
	} else {
		logger.LogError("ConfigurePlugin: plugin does not support initialization",
			logger.String("type", pluginType),
			logger.String("plugin", pluginName))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "plugin does not support initialization"})
	}

	logger.LogInfo("ConfigurePlugin: plugin configured", logger.String("type", pluginType), logger.String("plugin", pluginName))
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "plugin configured"})
}

// ExchangeRateWorker updates exchange rates automatically at scheduled intervals
func ExchangeRateWorker(store *PostgresStore, serverConfig *server_config.Service) {
	ctx := context.Background()
	logger.LogInfo("exchange_rate.worker.starting")

	// Configure which currencies to update
	majorCurrencies := []string{"USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "CNY", "HKD", "SGD"}

	// Default update interval is 24 hours (daily updates)
	updateInterval := 24 * time.Hour

	for {
		// Get configuration from server config if available
		var source string
		var apiKey string
		var baseCurrency string

		if serverConfig != nil {
			// Try to get exchange rate provider config
			exchCfg, err := serverConfig.Get(ctx, "exchange_rate")
			if err == nil && exchCfg.Value != "" {
				// Parse the JSON config
				var cfg map[string]interface{}
				if jsonErr := json.Unmarshal([]byte(exchCfg.Value), &cfg); jsonErr == nil {
					if s, ok := cfg["source"].(string); ok && s != "" {
						source = s
					}
					if key, ok := cfg["api_key"].(string); ok && key != "" {
						apiKey = key
					}
					if base, ok := cfg["base_currency"].(string); ok && base != "" {
						baseCurrency = base
					}
					if interval, ok := cfg["update_interval"].(string); ok && interval != "" {
						// Try to parse interval (e.g., "12h", "1d", etc.)
						if d, err := time.ParseDuration(interval); err == nil && d > 0 {
							updateInterval = d
						}
					}
				}
			}
		}

		// Default values if not configured
		if source == "" {
			source = "ecb" // European Central Bank (free, no API key required)
		}
		if baseCurrency == "" {
			baseCurrency = "EUR" // Default base currency
		}

		logger.LogInfo("exchange_rate.worker.updating",
			logger.String("source", source),
			logger.String("base_currency", baseCurrency))

		// URLs for different external rate providers
		var ratesURL string
		var client = http.Client{
			Timeout: 30 * time.Second,
		}

		switch strings.ToLower(source) {
		case "ecb":
			// European Central Bank (free, no API key)
			ratesURL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
		case "fixer":
			// Fixer.io (requires API key)
			if apiKey == "" {
				logger.LogError("exchange_rate.worker.missing_api_key", logger.String("source", source))
				time.Sleep(updateInterval)
				continue
			}
			ratesURL = fmt.Sprintf("http://data.fixer.io/api/latest?access_key=%s&base=%s", apiKey, baseCurrency)
		case "openexchangerates":
			// Open Exchange Rates (requires API key)
			if apiKey == "" {
				logger.LogError("exchange_rate.worker.missing_api_key", logger.String("source", source))
				time.Sleep(updateInterval)
				continue
			}
			ratesURL = fmt.Sprintf("https://openexchangerates.org/api/latest.json?app_id=%s&base=%s", apiKey, baseCurrency)
		default:
			logger.LogError("exchange_rate.worker.unsupported_source", logger.String("source", source))
			time.Sleep(updateInterval)
			continue
		}

		// Make HTTP request to get exchange rates
		req, err := http.NewRequestWithContext(ctx, "GET", ratesURL, nil)
		if err != nil {
			logger.LogError("exchange_rate.worker.request_creation_failed", logger.ErrorField(err))
			time.Sleep(updateInterval)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			logger.LogError("exchange_rate.worker.request_failed", logger.ErrorField(err))
			time.Sleep(updateInterval)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			logger.LogError("exchange_rate.worker.api_error", logger.Int("status_code", resp.StatusCode))
			resp.Body.Close()
			time.Sleep(updateInterval)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logger.LogError("exchange_rate.worker.read_body_failed", logger.ErrorField(err))
			time.Sleep(updateInterval)
			continue
		}

		// Parse response based on source
		rates := make(map[string]float64)

		switch strings.ToLower(source) {
		case "ecb":
			// Parse XML from ECB
			var ecbData struct {
				Cube struct {
					Cube struct {
						Cube []struct {
							Currency string  `xml:"currency,attr"`
							Rate     float64 `xml:"rate,attr"`
						} `xml:"Cube"`
					} `xml:"Cube"`
				} `xml:"Cube"`
			}
			if err := xml.Unmarshal(body, &ecbData); err != nil {
				logger.LogError("exchange_rate.worker.parse_xml_failed", logger.ErrorField(err))
				time.Sleep(updateInterval)
				continue
			}

			for _, cube := range ecbData.Cube.Cube.Cube {
				rates[cube.Currency] = cube.Rate
			}

			// ECB uses EUR as base, so we need to handle conversions if baseCurrency is not EUR
			if baseCurrency != "EUR" {
				// Check if we have a rate for the requested base currency
				baseRate, ok := rates[baseCurrency]
				if !ok {
					logger.LogError("exchange_rate.worker.base_currency_not_found",
						logger.String("base_currency", baseCurrency))
					time.Sleep(updateInterval)
					continue
				}

				// Adjust all rates to the new base
				for curr, rate := range rates {
					rates[curr] = rate / baseRate
				}
				// Add EUR rate
				rates["EUR"] = 1.0 / baseRate
			}

		case "fixer", "openexchangerates":
			// Parse JSON from Fixer or Open Exchange Rates
			var data struct {
				Success bool               `json:"success"`
				Base    string             `json:"base"`
				Rates   map[string]float64 `json:"rates"`
				Error   struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}

			if err := json.Unmarshal(body, &data); err != nil {
				logger.LogError("exchange_rate.worker.parse_json_failed", logger.ErrorField(err))
				time.Sleep(updateInterval)
				continue
			}

			// Check for API-specific errors
			if !data.Success {
				logger.LogError("exchange_rate.worker.api_error_response",
					logger.String("error_code", data.Error.Code),
					logger.String("error_message", data.Error.Message))
				time.Sleep(updateInterval)
				continue
			}

			rates = data.Rates
		}

		// Store rates in database
		updatedCount := 0

		for _, currency := range majorCurrencies {
			if currency == baseCurrency {
				// Skip base currency against itself
				continue
			}

			rate, ok := rates[currency]
			if !ok {
				logger.LogWarn("exchange_rate.worker.currency_not_found",
					logger.String("currency", currency))
				continue
			}

			// Create exchange rate record
			exchangeRate := ExchangeRate{
				ID:            commonutil.GenerateUUID(),
				BaseCurrency:  baseCurrency,
				QuoteCurrency: currency,
				Rate:          rate,
				Source:        source,
				UpdatedAt:     time.Now().UTC(),
			}

			// Store in database
			_, err := store.CreateExchangeRate(ctx, exchangeRate)
			if err != nil {
				logger.LogError("exchange_rate.worker.store_rate_failed",
					logger.ErrorField(err),
					logger.String("base", exchangeRate.BaseCurrency),
					logger.String("quote", exchangeRate.QuoteCurrency))
				continue
			}

			updatedCount++
		}

		logger.LogInfo("exchange_rate.worker.rates_updated",
			logger.Int("count", updatedCount),
			logger.String("source", source),
			logger.String("base", baseCurrency))

		// Sleep until next update
		time.Sleep(updateInterval)
	}
}

// --- Dunning Configuration Handlers ---

// GetDunningConfig retrieves the current dunning configuration for a tenant
func (h *BillingAdminHandler) GetDunningConfig(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetDunningConfig: missing tenant ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "error occured",
		})
	}

	config, err := h.DunningService.GetDunningConfig(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetDunningConfig: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve dunning configuration",
		})
	}

	if config == nil {
		// No configuration found, return default values
		return c.JSON(fiber.Map{
			"tenant_id":    tenantID,
			"max_attempts": 3,
			"retry_intervals": []string{
				"24h",
				"48h",
				"72h",
			},
		})
	}

	// Convert durations to strings for easier client handling
	intervals := make([]string, len(config.RetryIntervals))
	for i, duration := range config.RetryIntervals {
		intervals[i] = duration.String()
	}

	return c.JSON(fiber.Map{
		"tenant_id":       tenantID,
		"max_attempts":    config.MaxAttempts,
		"retry_intervals": intervals,
	})
}

// UpdateDunningConfig updates the dunning configuration for a tenant
func (h *BillingAdminHandler) UpdateDunningConfig(c *fiber.Ctx) error {
	var input struct {
		TenantID       string   `json:"tenant_id"`
		MaxAttempts    int      `json:"max_attempts"`
		RetryIntervals []string `json:"retry_intervals"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDunningConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	if input.TenantID == "" {
		logger.LogError("UpdateDunningConfig: tenant_id required", logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	if input.MaxAttempts < 1 || input.MaxAttempts > 10 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "max_attempts must be between 1 and 10",
		})
	}

	if len(input.RetryIntervals) != input.MaxAttempts {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("retry_intervals length must match max_attempts (%d)", input.MaxAttempts),
		})
	}

	// Validate and parse retry intervals
	intervals := make([]time.Duration, len(input.RetryIntervals))
	for i, intervalStr := range input.RetryIntervals {
		duration, err := time.ParseDuration(intervalStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("invalid duration format at position %d: %s (use 1h, 24h, 7d format)", i, intervalStr),
			})
		}
		if duration < 1*time.Hour || duration > 30*24*time.Hour {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("interval at position %d must be between 1 hour and 30 days", i),
			})
		}
		intervals[i] = duration
	}

	// Create DunningConfig object
	config := &payment.DunningConfig{
		MaxAttempts:    input.MaxAttempts,
		RetryIntervals: intervals,
	}

	// Store the configuration using the DunningService
	if err := h.DunningService.UpdateDunningConfig(c.Context(), input.TenantID, config); err != nil {
		logger.LogError("UpdateDunningConfig: failed to save", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(fiber.Map{
		"tenant_id":       input.TenantID,
		"max_attempts":    input.MaxAttempts,
		"retry_intervals": input.RetryIntervals,
		"status":          "success",
	})
}

// ManualRetryDunning allows an admin to manually retry a failed payment for an invoice
func (h *BillingAdminHandler) ManualRetryDunning(c *fiber.Ctx) error {
	invoiceID := c.Params("id")
	if invoiceID == "" {
		logger.LogError("ManualRetryDunning: missing invoice ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "error occured",
		})
	}

	// Use the dunning service to retry the payment
	err := h.DunningService.ManualRetryDunning(c.Context(), invoiceID)
	if err != nil {
		logger.LogError("ManualRetryDunning: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Payment processing failed",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":    true,
		"message":    "Payment successful",
		"status":     "paid",
		"invoice_id": invoiceID,
	})
}

// GetDunningEvents returns the history of dunning events for a specific invoice
func (h *BillingAdminHandler) GetDunningEvents(c *fiber.Ctx) error {
	invoiceID := c.Params("id")
	if invoiceID == "" {
		logger.LogError("GetDunningEvents: invoice_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	// Get pagination parameters
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "10"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Retrieve the events from the service
	events, err := h.DunningService.GetDunningEvents(c.Context(), invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("GetDunningEvents: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(fiber.Map{
		"events": events,
		"pagination": fiber.Map{
			"page":         page,
			"page_size":    pageSize,
			"total_events": len(events), // This should ideally be a count query
		},
	})
}

// GetDunningDashboard returns stats about the dunning system
func (h *BillingAdminHandler) GetDunningDashboard(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetDunningDashboard: tenant_id required")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing required parameter",
		})
	}

	// Get the dashboard data from the service
	dashboard, err := h.DunningService.GetDunningDashboard(c.Context(), tenantID)
	if err != nil {
		logger.LogError("GetDunningDashboard: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process request",
		})
	}

	return c.JSON(dashboard)
}

// getPaymentMethodOrDefault safely extracts a payment method from a payment result
func getPaymentMethodOrDefault(result *payment.PaymentResult) string {
	if result == nil {
		return ""
	}

	// Try to extract method from Raw field which may contain a map
	if result.Raw != nil {
		if m, ok := result.Raw.(map[string]interface{}); ok {
			if method, ok := m["method"].(string); ok {
				return method
			}
		}
	}

	return "unknown" // Fallback value
}

// validateAccountAccess checks if the account in the request belongs to the tenant
// Returns true if access is allowed, false if not
func (h *BillingAdminHandler) validateAccountAccess(c *fiber.Ctx, accountID string) bool {
	if accountID == "" {
		return true
	}

	tenantID := GetTenantIDFromContext(c.Context())
	if tenantID == "" {
		return false
	}

	// Try project account
	acct, err := h.AccountService.Get(c.Context(), account.AccountTypeProject, accountID)
	if err == nil {
		if acctMap, ok := acct.(map[string]interface{}); ok {
			if tid, ok := acctMap["tenant_id"].(string); ok && tid == tenantID {
				return true
			}
		}
		if projectAcct, ok := acct.(*account.ProjectBillingAccount); ok && projectAcct.TenantID == tenantID {
			return true
		}
	}

	// Try user account
	acct, err = h.AccountService.Get(c.Context(), account.AccountTypeUser, accountID)
	if err == nil {
		if acctMap, ok := acct.(map[string]interface{}); ok {
			if tid, ok := acctMap["tenant_id"].(string); ok && tid == tenantID {
				return true
			}
		}
		if userAcct, ok := acct.(*account.UserBillingAccount); ok && userAcct.TenantID == tenantID {
			return true
		}
	}

	// Try organization account
	acct, err = h.AccountService.Get(c.Context(), account.AccountTypeOrganization, accountID)
	if err == nil {
		if acctMap, ok := acct.(map[string]interface{}); ok {
			if tid, ok := acctMap["tenant_id"].(string); ok && tid == tenantID {
				return true
			}
		}
		if orgAcct, ok := acct.(*account.OrganizationBillingAccount); ok && orgAcct.TenantID == tenantID {
			return true
		}
	}

	return false
}
