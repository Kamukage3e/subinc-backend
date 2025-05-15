package billing_management

import (
	"bytes"
	"fmt"
	"time"

	"strings"

	"github.com/gofiber/fiber/v2"
	// "github.com/google/uuid"
	"github.com/jung-kurt/gofpdf"

	"os"

	"context"

	"github.com/stripe/stripe-go/v75/webhook"
	account "github.com/subinc/subinc-backend/internal/admin/billing-management/account"
	"github.com/subinc/subinc-backend/internal/admin/billing-management/payment"
	tax "github.com/subinc/subinc-backend/internal/admin/billing-management/tax"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Payment, Refund, and PaymentMethod logic is now handled exclusively in internal/admin/billing-management/payment/handlers.go

func NewBillingHandler(store *PostgresStore, paymentStore payment.StoreInterface) *BillingAdminHandler {
	return &BillingAdminHandler{Store: store, PaymentStore: paymentStore}
}

// swagger:route POST /billing-management/webhook-events/create billing webhookEventCreate
// ---
// summary: Create a webhook event
// description: Creates a new webhook event.
// tags:
//   - billing
//   - webhook
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/WebhookEvent"
//
// responses:
//
//	201:
//	  description: WebhookEvent
//	  schema:
//	    $ref: "#/definitions/WebhookEvent"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	event, err := h.WebhookEventService.CreateWebhookEvent(input)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(event)
}

// swagger:route PUT /billing-management/webhook-events/update billing webhookEventUpdate
// ---
// summary: Update a webhook event
// description: Updates an existing webhook event.
// tags:
//   - billing
//   - webhook
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/WebhookEvent"
//
// responses:
//
//	200:
//	  description: WebhookEvent
//	  schema:
//	    $ref: "#/definitions/WebhookEvent"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) UpdateWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateWebhookEvent: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input WebhookEvent
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	event, err := h.WebhookEventService.UpdateWebhookEvent(input)
	if err != nil {
		logger.LogError("UpdateWebhookEvent: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(event)
}

// swagger:route DELETE /billing-management/webhook-events/delete billing webhookEventDelete
// ---
// summary: Delete a webhook event
// description: Deletes a webhook event by ID.
// tags:
//   - billing
//   - webhook
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) DeleteWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteWebhookEvent: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookEventService.DeleteWebhookEvent(id); err != nil {
		logger.LogError("DeleteWebhookEvent: failed", logger.ErrorField(err), logger.String("id", id))
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

// swagger:route GET /billing-management/webhook-events/get billing webhookEventGet
// ---
// summary: Get a webhook event
// description: Retrieves a webhook event by ID.
// tags:
//   - billing
//   - webhook
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	200:
//	  description: WebhookEvent
//	  schema:
//	    $ref: "#/definitions/WebhookEvent"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	404:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetWebhookEvent(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetWebhookEvent: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	event, err := h.WebhookEventService.GetWebhookEvent(id)
	if err != nil {
		logger.LogError("GetWebhookEvent: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(event)
}

// swagger:route GET /billing-management/webhook-events/list billing webhookEventList
// ---
// summary: List webhook events
// description: Lists webhook events with optional filters.
// tags:
//   - billing
//   - webhook
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: false
//     schema:
//     type: object
//     properties:
//     account_id:
//     type: string
//     status:
//     type: string
//     page:
//     type: integer
//     page_size:
//     type: integer
//
// responses:
//
//	200:
//	  description: WebhookEventListResponse
//	  schema:
//	    $ref: "#/definitions/WebhookEventListResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ListWebhookEvents(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_event", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	events, err := h.WebhookEventService.ListWebhookEvents(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListWebhookEvents: failed", logger.ErrorField(err), logger.String("account_id", accountID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"webhook_events": events, "page": page, "page_size": pageSize})
}

// swagger:route POST /billing-management/invoice-adjustments/create billing invoiceAdjustmentCreate
// ---
// summary: Create an invoice adjustment
// description: Creates a new invoice adjustment.
// tags:
//   - billing
//   - invoice-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/InvoiceAdjustment"
//
// responses:
//
//	201:
//	  description: InvoiceAdjustment
//	  schema:
//	    $ref: "#/definitions/InvoiceAdjustment"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoiceAdjustment: validation failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := any(err).(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	adj, err := h.InvoiceAdjustmentService.CreateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("CreateInvoiceAdjustment: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(adj)
}

// swagger:route PUT /billing-management/invoice-adjustments/update billing invoiceAdjustmentUpdate
// ---
// summary: Update an invoice adjustment
// description: Updates an existing invoice adjustment.
// tags:
//   - billing
//   - invoice-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/InvoiceAdjustment"
//
// responses:
//
//	200:
//	  description: InvoiceAdjustment
//	  schema:
//	    $ref: "#/definitions/InvoiceAdjustment"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) UpdateInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateInvoiceAdjustment: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoiceAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	adj, err := h.InvoiceAdjustmentService.UpdateInvoiceAdjustment(input)
	if err != nil {
		logger.LogError("UpdateInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(adj)
}

// swagger:route DELETE /billing-management/invoice-adjustments/delete billing invoiceAdjustmentDelete
// ---
// summary: Delete an invoice adjustment
// description: Deletes an invoice adjustment by ID.
// tags:
//   - billing
//   - invoice-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) DeleteInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteInvoiceAdjustment: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.InvoiceAdjustmentService.DeleteInvoiceAdjustment(id); err != nil {
		logger.LogError("DeleteInvoiceAdjustment: failed", logger.ErrorField(err), logger.String("id", id))
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

// swagger:route GET /billing-management/invoice-adjustments/get billing invoiceAdjustmentGet
// ---
// summary: Get an invoice adjustment
// description: Retrieves an invoice adjustment by ID.
// tags:
//   - billing
//   - invoice-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	200:
//	  description: InvoiceAdjustment
//	  schema:
//	    $ref: "#/definitions/InvoiceAdjustment"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	404:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetInvoiceAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetInvoiceAdjustment: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	adj, err := h.InvoiceAdjustmentService.GetInvoiceAdjustment(id)
	if err != nil {
		logger.LogError("GetInvoiceAdjustment: not found", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(adj)
}

// swagger:route GET /billing-management/invoice-adjustments/list billing invoiceAdjustmentList
// ---
// summary: List invoice adjustments
// description: Lists invoice adjustments with optional filters.
// tags:
//   - billing
//   - invoice-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: false
//     schema:
//     type: object
//     properties:
//     invoice_id:
//     type: string
//     page:
//     type: integer
//     page_size:
//     type: integer
//
// responses:
//
//	200:
//	  description: InvoiceAdjustmentListResponse
//	  schema:
//	    $ref: "#/definitions/InvoiceAdjustmentListResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ListInvoiceAdjustments(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_adjustment", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	invoiceID := c.Query("invoice_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	adjs, err := h.InvoiceAdjustmentService.ListInvoiceAdjustments(invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments: failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"invoice_adjustments": adjs, "page": page, "page_size": pageSize})
}

// swagger:route POST /billing-management/manual-adjustment/create billing manualAdjustmentCreate
// ---
// summary: Create a manual adjustment
// description: Creates a manual adjustment for an invoice.
// tags:
//   - billing
//   - manual-adjustment
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/InvoiceAdjustment"
//
// responses:
//
//	201:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateManualAdjustment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "manual_adjustment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input InvoiceAdjustment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualAdjustment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateManualAdjustment: validation failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := any(err).(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	// InvoiceAdjustment does not have AccountID, use InvoiceID as the identifier for manual adjustment
	err := h.ManualAdjustmentService.CreateManualAdjustment(input.InvoiceID, input.Reason, input.Amount, input.Currency)
	if err != nil {
		logger.LogError("CreateManualAdjustment: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusCreated)
}

// swagger:route GET /billing-management/accounts/invoice-preview billing invoicePreviewGet
// ---
// summary: Get invoice preview
// description: Returns a preview of an invoice by ID.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetInvoicePreview(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)

		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice_preview", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		logger.LogError("GetInvoicePreview: id required", logger.String("id", input.ID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(input.ID); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err), logger.String("id", input.ID))
		errResp := fiber.Map{"error": "failed to delete payment method"}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route POST /billing-management/invoices/apply-credits billing invoiceApplyCredits
// ---
// summary: Apply credits to invoice
// description: Applies available credits to an invoice.
// tags:
//   - billing
//   - invoice
//   - credit
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     invoice_id:
//     type: string
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ApplyCreditsToInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)

		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "credit", "apply")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		logger.LogError("ApplyCreditsToInvoice: invoice_id required", logger.String("invoice_id", input.InvoiceID))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	if err := h.CreditService.ApplyCreditsToInvoice(input.InvoiceID); err != nil {
		logger.LogError("ApplyCreditsToInvoice: failed", logger.ErrorField(err), logger.String("invoice_id", input.InvoiceID))
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

// swagger:route GET /billing-management/billing/config/get billing billingConfigGet
// ---
// summary: Get billing config
// description: Retrieves the current billing configuration.
// tags:
//   - billing
//   - config
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// responses:
//
//	200:
//	  description: BillingConfigResponse
//	  schema:
//	    $ref: "#/definitions/BillingConfigResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetBillingConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_config", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input) // Accepts empty body for consistency
	cfg, err := h.InvoiceService.GetBillingConfig()
	if err != nil {
		logger.LogError("GetBillingConfig: failed", logger.ErrorField(err))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(cfg)
}

// swagger:route POST /billing-management/billing/config/set billing billingConfigSet
// ---
// summary: Set billing config
// description: Sets the billing configuration.
// tags:
//   - billing
//   - config
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) SetBillingConfig(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "billing_config", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input map[string]interface{}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetBillingConfig: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.InvoiceService.SetBillingConfig(input); err != nil {
		logger.LogError("SetBillingConfig: failed", logger.ErrorField(err))
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

// swagger:route POST /billing-management/webhook-subscriptions/create billing webhookSubscriptionCreate
// ---
// summary: Create a webhook subscription
// description: Creates a new webhook subscription.
// tags:
//   - billing
//   - webhook-subscription
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     url:
//     type: string
//     secret:
//     type: string
//     description:
//     type: string
//     events:
//     type: array
//     items:
//     type: string
//
// responses:
//
//	201:
//	  description: Created
//	  schema:
//	    type: string
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
func (h *BillingAdminHandler) CreateWebhookSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.SendStatus(fiber.StatusCreated)
}

// swagger:route GET /billing-management/webhook-subscriptions/list billing webhookSubscriptionList
// ---
// summary: List webhook subscriptions
// description: Lists webhook subscriptions for a tenant.
// tags:
//   - billing
//   - webhook-subscription
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: false
//     schema:
//     type: object
//     properties:
//     tenant_id:
//     type: string
//     page:
//     type: integer
//     page_size:
//     type: integer
//
// responses:
//
//	200:
//	  description: List of webhook subscriptions
//	  schema:
//	    type: object
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ListWebhookSubscriptions(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
	out, err := h.WebhookSubscriptionService.ListWebhookSubscriptions(input.TenantID, input.Page, input.PageSize)
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(out)
}

// swagger:route DELETE /billing-management/webhook-subscriptions/delete billing webhookSubscriptionDelete
// ---
// summary: Delete a webhook subscription
// description: Deletes a webhook subscription by ID.
// tags:
//   - billing
//   - webhook-subscription
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     id:
//     type: string
//
// responses:
//
//	204:
//	  description: No Content
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
func (h *BillingAdminHandler) DeleteWebhookSubscription(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "webhook_subscription", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		ID string `json:"id"`
	}
	if err := c.BodyParser(&input); err != nil || input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.WebhookSubscriptionService.DeleteWebhookSubscription(input.ID); err != nil {
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

// swagger:route GET /billing-management/reports/revenue billing revenueReportGet
// ---
// summary: Get revenue report
// description: Retrieves the revenue report.
// tags:
//   - billing
//   - report
//
// produces:
//   - application/json
//
// responses:
//
//	200:
//	  description: Revenue report
//	  schema:
//	    type: object
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetRevenueReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "revenue_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetRevenueReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(out)
}

// swagger:route GET /billing-management/reports/ar billing arReportGet
// ---
// summary: Get accounts receivable report
// description: Retrieves the accounts receivable report.
// tags:
//   - billing
//   - report
//
// produces:
//   - application/json
//
// responses:
//
//	200:
//	  description: Accounts receivable report
//	  schema:
//	    type: object
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetARReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "ar_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetARReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(out)
}

// swagger:route GET /billing-management/reports/churn billing churnReportGet
// ---
// summary: Get churn report
// description: Retrieves the churn report.
// tags:
//   - billing
//   - report
//
// produces:
//   - application/json
//
// responses:
//
//	200:
//	  description: Churn report
//	  schema:
//	    type: object
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetChurnReport(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "churn_report", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct{}
	_ = c.BodyParser(&input)
	out, err := h.Store.GetChurnReport(c.Context())
	if err != nil {
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.JSON(out)
}

// swagger:route POST /billing-management/invoices/create-with-fees billing invoiceCreateWithFees
// ---
// summary: Create invoice with fees and tax
// description: Creates an invoice with additional fees and tax.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     invoice:
//     $ref: "#/definitions/Invoice"
//     fixed_fee:
//     type: number
//     percent_fee:
//     type: number
//     tax_rate:
//     type: number
//
// responses:
//
//	201:
//	  description: Invoice
//	  schema:
//	    $ref: "#/definitions/Invoice"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateInvoiceWithFeesAndTax(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	return c.Status(fiber.StatusCreated).JSON(out)
}

// swagger:route POST /billing-management/invoices/create billing invoiceCreate
// ---
// summary: Create an invoice
// description: Creates a new invoice.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/Invoice"
//
// responses:
//
//	201:
//	  description: Invoice
//	  schema:
//	    $ref: "#/definitions/Invoice"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := input.Validate(); err != nil {
		logger.LogError("CreateInvoice: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	account, err := h.AccountService.GetAccount(input.AccountID)
	if err != nil {
		logger.LogError("CreateInvoice: account not found", logger.ErrorField(err), logger.String("account_id", input.AccountID))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "account not found"})
	}
	currency := strings.ToUpper(strings.TrimSpace(input.Currency))
	if currency == "" {
		currency = strings.ToUpper(strings.TrimSpace(account.Currency))
		if currency == "" {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no currency set for invoice or account"})
		}
		input.Currency = currency
	}
	if input.Currency != account.Currency && account.Currency != "" {
		rate, rerr := h.Store.GetExchangeRate(c.Context(), input.Currency, account.Currency)
		if rerr != nil || rate.Rate <= 0 {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no valid exchange rate from " + input.Currency + " to " + account.Currency})
		}
		input.OriginalAmount = input.Amount
		input.OriginalCurrency = input.Currency
		input.Amount = input.Amount * rate.Rate
		input.Currency = account.Currency
	}
	// --- Tax plugin selection and calculation ---
	pluginName := "default"
	if cfg, err := h.TaxService.GetTaxPluginConfig(c.Context(), account.TenantID); err == nil && cfg.PluginName != "" {
		pluginName = cfg.PluginName
	}
	plugin, ok := tax.TaxPlugins.Lookup(pluginName)
	if !ok {
		plugin = tax.DefaultTaxPlugin{}
	}
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
	taxAmount, taxRate, terr := plugin.CalculateTax(c.Context(), taxInvoice, tax.Account(account), account.TenantID)
	if terr != nil {
		logger.LogError("CreateInvoice: tax plugin failed", logger.ErrorField(terr), logger.String("plugin", pluginName))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tax calculation failed: " + terr.Error()})
	}
	input.TaxAmount = taxAmount
	input.TaxRate = taxRate
	invoice, err := h.InvoiceService.CreateInvoice(input)
	if err != nil {
		logger.LogError("CreateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}

	// --- Send notification (non-blocking) ---
	if h.Notify != nil && account.Email != "" {
		go func(inv Invoice) {
			acct, accErr := h.AccountService.GetAccount(inv.AccountID)
			if accErr != nil || acct.Email == "" {
				logger.LogError("dunning.worker.notify.account_not_found", logger.ErrorField(accErr), logger.String("account_id", inv.AccountID))
				return
			}
			details := map[string]interface{}{
				"invoice_id":    inv.ID,
				"amount":        inv.Amount,
				"currency":      inv.Currency,
				"due_date":      inv.DueDate,
				"status":        inv.Status,
				"account_id":    acct.ID,
				"account_email": acct.Email,
				"tenant_id":     acct.TenantID,
			}
			err := h.Notify.SendNotification(
				context.Background(),
				acct.TenantID,
				security_management.NotificationEmail,
				[]string{acct.Email},
				"invoice.issued",
				details,
				3,
			)
			if err != nil {
				logger.LogError("dunning.worker.notify.failed", logger.ErrorField(err), logger.String("account_id", acct.ID))
			}
		}(invoice)
	}

	return c.Status(fiber.StatusCreated).JSON(invoice)
}

// swagger:route PUT /billing-management/invoices/update billing invoiceUpdate
// ---
// summary: Update an invoice
// description: Updates an existing invoice.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/Invoice"
//
// responses:
//
//	200:
//	  description: Invoice
//	  schema:
//	    $ref: "#/definitions/Invoice"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) UpdateInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateInvoice: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input Invoice
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateInvoice: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	if err := input.Validate(); err != nil {
		logger.LogError("UpdateInvoice: validation failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Message, "code": err.Code, "field": err.Field})
	}
	invoice, err := h.InvoiceService.UpdateInvoice(input)
	if err != nil {
		logger.LogError("UpdateInvoice: failed", logger.ErrorField(err), logger.Any("input", input))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(invoice)
}

// swagger:route GET /billing-management/invoices/get billing invoiceGet
// ---
// summary: Get an invoice
// description: Retrieves an invoice by ID.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     invoice_id:
//     type: string
//
// responses:
//
//	200:
//	  description: Invoice
//	  schema:
//	    $ref: "#/definitions/Invoice"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	404:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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

// swagger:route GET /billing-management/invoices/list billing invoiceList
// ---
// summary: List invoices
// description: Lists invoices with optional filters.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: false
//     schema:
//     type: object
//     properties:
//     account_id:
//     type: string
//     status:
//     type: string
//     page:
//     type: integer
//     page_size:
//     type: integer
//
// responses:
//
//	200:
//	  description: List of invoices
//	  schema:
//	    type: object
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ListInvoices(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	accountID := c.Query("account_id")
	status := c.Query("status")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	invoices, err := h.InvoiceService.ListInvoices(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListInvoices: failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("status", status))
		errResp := fiber.Map{"error": err.Error()}
		if apiErr, ok := err.(*Error); ok {
			errResp["error"] = apiErr.Message
			errResp["code"] = apiErr.Code
			errResp["field"] = apiErr.Field
		}
		return c.Status(fiber.StatusUnprocessableEntity).JSON(errResp)
	}
	return c.JSON(fiber.Map{"invoices": invoices, "page": page, "page_size": pageSize})
}

// --- ExchangeRate Handlers ---

// swagger:route POST /billing-management/exchange-rates/create billing exchangeRateCreate
// ---
// summary: Create an exchange rate
// description: Creates a new exchange rate.
// tags:
//   - billing
//   - exchange-rate
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/ExchangeRate"
//
// responses:
//
//	201:
//	  description: ExchangeRate
//	  schema:
//	    $ref: "#/definitions/ExchangeRate"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) CreateExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(rate)
}

// swagger:route PUT /billing-management/exchange-rates/update billing exchangeRateUpdate
// ---
// summary: Update an exchange rate
// description: Updates an existing exchange rate.
// tags:
//   - billing
//   - exchange-rate
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/ExchangeRate"
//
// responses:
//
//	200:
//	  description: ExchangeRate
//	  schema:
//	    $ref: "#/definitions/ExchangeRate"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) UpdateExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(rate)
}

// swagger:route DELETE /billing-management/exchange-rates/delete billing exchangeRateDelete
// ---
// summary: Delete an exchange rate
// description: Deletes an exchange rate by base and quote currency.
// tags:
//   - billing
//   - exchange-rate
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     base_currency:
//     type: string
//     quote_currency:
//     type: string
//
// responses:
//
//	204:
//	  description: EmptyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) DeleteExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// swagger:route GET /billing-management/exchange-rates/get billing exchangeRateGet
// ---
// summary: Get an exchange rate
// description: Retrieves an exchange rate by base and quote currency.
// tags:
//   - billing
//   - exchange-rate
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     base_currency:
//     type: string
//     quote_currency:
//     type: string
//
// responses:
//
//	200: ExchangeRate
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetExchangeRate(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
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
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(rate)
}

// swagger:route GET /billing-management/exchange-rates/list billing exchangeRateList
// ---
// summary: List exchange rates
// description: Lists all exchange rates.
// tags:
//   - billing
//   - exchange-rate
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// responses:
//
//	200: ExchangeRateListResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) ListExchangeRates(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "exchange_rate", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	rates, err := h.Store.ListExchangeRates(c.Context())
	if err != nil {
		logger.LogError("ListExchangeRates: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"exchange_rates": rates})
}

// --- TenantCurrency Handlers ---

// swagger:route POST /billing-management/tenant-currency/set billing tenantCurrencySet
// ---
// summary: Set tenant currency
// description: Sets the currency for a tenant.
// tags:
//   - billing
//   - tenant-currency
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     tenant_id:
//     type: string
//     currency:
//     type: string
//
// responses:
//
//	201: TenantCurrencyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//
//	400: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//
//	422: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) SetTenantCurrency(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_currency", "set")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
		Currency string `json:"currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("SetTenantCurrency: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.TenantID == "" || input.Currency == "" {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tenant_id and currency required"})
	}
	curr, err := h.Store.SetTenantCurrency(c.Context(), input.TenantID, input.Currency)
	if err != nil {
		logger.LogError("SetTenantCurrency: failed", logger.ErrorField(err), logger.Any("input", input))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(curr)
}

// swagger:route GET /billing-management/tenant-currency/get billing tenantCurrencyGet
// ---
// summary: Get tenant currency
// description: Retrieves the currency for a tenant.
// tags:
//   - billing
//   - tenant-currency
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     tenant_id:
//     type: string
//
// responses:
//
//	200: TenantCurrencyResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	400: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
//	422: ErrorResponse
//	  headers:
//	    X-Request-ID:
//	      type: string
//	      description: Unique request ID
func (h *BillingAdminHandler) GetTenantCurrency(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "tenant_currency", "get")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		TenantID string `json:"tenant_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.TenantID == "" {
		logger.LogError("GetTenantCurrency: tenant_id required", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id required"})
	}
	curr, err := h.Store.GetTenantCurrency(c.Context(), input.TenantID)
	if err != nil {
		logger.LogError("GetTenantCurrency: failed", logger.ErrorField(err), logger.String("tenant_id", input.TenantID))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(curr)
}

func generateInvoicePDF(pdfData map[string]interface{}) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	if title, ok := pdfData["title"].(string); ok && title != "" {
		pdf.SetTitle(title, false)
	}
	pdf.AddPage()

	// Logo (optional)
	if logo, ok := pdfData["logo"].(string); ok && logo != "" {
		pdf.ImageOptions(logo, 10, 10, 30, 0, false, gofpdf.ImageOptions{}, 0, "")
		pdf.Ln(20)
	}

	// Header lines (optional)
	if header, ok := pdfData["header"].([]string); ok {
		pdf.SetFont("Arial", "B", 20)
		for _, line := range header {
			pdf.Cell(0, 12, line)
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Fields (label/value pairs)
	if fields, ok := pdfData["fields"].([][2]string); ok {
		pdf.SetFont("Arial", "", 12)
		for _, pair := range fields {
			pdf.Cell(40, 8, pair[0])
			pdf.Cell(0, 8, pair[1])
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Table (rows: description, amount, currency)
	if table, ok := pdfData["table"].([][3]string); ok && len(table) > 0 {
		pdf.SetFont("Arial", "B", 12)
		pdf.Cell(60, 8, "Description")
		pdf.Cell(40, 8, "Amount")
		pdf.Cell(40, 8, "Currency")
		pdf.Ln(8)
		pdf.SetFont("Arial", "", 12)
		for _, row := range table {
			pdf.Cell(60, 8, row[0])
			pdf.Cell(40, 8, row[1])
			pdf.Cell(40, 8, row[2])
			pdf.Ln(8)
		}
		pdf.Ln(4)
	}

	// Footer/notes (optional)
	if footer, ok := pdfData["footer"].(string); ok && footer != "" {
		pdf.SetFont("Arial", "I", 10)
		pdf.MultiCell(0, 7, footer, "", "L", false)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// swagger:route POST /billing-management/invoice/download billing invoiceDownload
// ---
// summary: Download invoice PDF
// description: Downloads the invoice PDF as an attachment. Only JSON body allowed.
// tags:
//   - billing
//   - invoice
//
// consumes:
//   - application/json
//
// produces:
//   - application/pdf
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     $ref: "#/definitions/InvoiceDownload"
//
// responses:
//
//	200:
//	  description: PDF
//	  schema:
//	    type: string
//	400:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"
//	404:
//	  description: ErrorResponse
//	  schema:
//	    $ref: "#/definitions/ErrorResponse"

// DownloadInvoicePDF returns the invoice PDF as an attachment. Only JSON body allowed.
func (h *BillingAdminHandler) DownloadInvoicePDF(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	var input struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := c.BodyParser(&input); err != nil || input.InvoiceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invoice_id required"})
	}
	invoice, err := h.InvoiceService.GetInvoice(input.InvoiceID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invoice not found"})
	}
	account, err := h.AccountService.GetAccount(invoice.AccountID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "account not found"})
	}
	pdfData := map[string]interface{}{
		"title":  "Invoice " + invoice.ID,
		"header": []string{"INVOICE"},
		"fields": [][2]string{
			{"Invoice ID:", invoice.ID},
			{"Status:", invoice.Status},
			{"Account Email:", account.Email},
			{"Account ID:", account.ID},
			{"Created:", invoice.CreatedAt.Format("2006-01-02 15:04")},
			{"Due Date:", invoice.DueDate.Format("2006-01-02")},
		},
		"table": [][3]string{
			{"Subtotal", fmt.Sprintf("%.2f", invoice.Amount-invoice.TaxAmount), invoice.Currency},
			{"Tax", fmt.Sprintf("%.2f (%.2f%%)", invoice.TaxAmount, invoice.TaxRate), invoice.Currency},
			{"Total", fmt.Sprintf("%.2f", invoice.Amount), invoice.Currency},
		},
		"footer": "Thank you for your business. If you have any questions, contact support@company.com.",
	}
	if invoice.OriginalAmount > 0 && invoice.OriginalCurrency != "" {
		table := pdfData["table"].([][3]string)
		table = append(table, [3]string{"Original Amount", fmt.Sprintf("%.2f", invoice.OriginalAmount), invoice.OriginalCurrency})
		pdfData["table"] = table
	}
	pdfBytes, pdfErr := generateInvoicePDF(pdfData)
	if pdfErr != nil {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{"error": pdfErr.Error()})
	}
	c.Set("Content-Type", "application/pdf")
	c.Set("Content-Disposition", "attachment; filename=invoice-"+invoice.ID+".pdf")

	return c.Send(pdfBytes)
}

// swagger:route POST /billing-management/stripe/webhook billing stripeWebhook
// ---
// summary: Stripe webhook handler
// description: Handles Stripe webhook events (invoice.paid, payment_intent.succeeded, invoice.payment_failed, customer.subscription.deleted, invoice.upcoming, invoice.finalized, invoice.voided, invoice.marked_uncollectible, charge.refunded, etc.).
// tags:
//   - billing
//   - webhook
//   - stripe
//
// consumes:
//   - application/json
//
// produces:
//   - application/json
//
// parameters:
//   - name: input
//     in: body
//     required: true
//     schema:
//     type: object
//     properties:
//     base_currency:
//     type: string
//     quote_currency:
//     type: string
//
// responses:
//
//	200:
//	  description: OK
//	  schema:
//	    type: string
func (h *BillingAdminHandler) StripeWebhookHandler(c *fiber.Ctx) error {
	const maxBodyBytes = int64(65536)
	body := c.BodyRaw()
	if int64(len(body)) > maxBodyBytes {
		logger.LogError("stripe.webhook.body_too_large")
		return c.SendStatus(fiber.StatusOK)
	}
	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if secret == "" {
		logger.LogError("stripe.webhook.secret_missing")
		return c.SendStatus(fiber.StatusOK)
	}
	sig := c.Get("Stripe-Signature")
	if sig == "" {
		logger.LogError("stripe.webhook.signature_missing")
		return c.SendStatus(fiber.StatusOK)
	}
	event, err := webhook.ConstructEvent(body, sig, secret)
	if err != nil {
		logger.LogError("stripe.webhook.invalid_signature", logger.ErrorField(err))
		return c.SendStatus(fiber.StatusOK)
	}
	processed, err := h.Store.IsStripeEventProcessed(c.Context(), event.ID)
	if err != nil {
		logger.LogError("stripe.webhook.idempotency_check_failed", logger.ErrorField(err), logger.String("event_id", event.ID))
		return c.SendStatus(fiber.StatusOK)
	}
	if processed {
		logger.LogInfo("stripe.webhook.duplicate_event", logger.String("event_id", event.ID), logger.String("type", string(event.Type)))
		return c.SendStatus(fiber.StatusOK)
	}
	logger.LogInfo("stripe.webhook.event_received", logger.String("type", string(event.Type)))
	switch event.Type {
	case "invoice.paid":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_paid.missing_id")
			break
		}
		err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "paid")
		if err != nil {
			logger.LogError("stripe.webhook.invoice_paid.update_failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		} else {
			logger.LogInfo("stripe.webhook.invoice_paid.updated", logger.String("invoice_id", invoiceID))
			h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
		}
	case "payment_intent.succeeded":
		intentObj := event.Data.Object
		invoiceID, ok := intentObj["invoice"].(string)
		if ok && invoiceID != "" {
			err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "paid")
			if err != nil {
				logger.LogError("stripe.webhook.payment_intent_succeeded.update_failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
			} else {
				logger.LogInfo("stripe.webhook.payment_intent_succeeded.updated", logger.String("invoice_id", invoiceID))
				h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
			}
		} else {
			logger.LogInfo("stripe.webhook.payment_intent_succeeded.no_invoice")
		}
	case "invoice.payment_failed":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_payment_failed.missing_id")
			break
		}
		err := h.Store.UpdateInvoiceStatus(c.Context(), invoiceID, "payment_failed")
		if err != nil {
			logger.LogError("stripe.webhook.invoice_payment_failed.update_failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		} else {
			logger.LogInfo("stripe.webhook.invoice_payment_failed.updated", logger.String("invoice_id", invoiceID))
			h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
		}
	case "customer.subscription.deleted":
		subObj := event.Data.Object
		subID, ok := subObj["id"].(string)
		if !ok || subID == "" {
			logger.LogError("stripe.webhook.subscription_deleted.missing_id")
			break
		}
		err := h.Store.UpdateSubscriptionStatus(c.Context(), subID, "canceled")
		if err != nil {
			logger.LogError("stripe.webhook.subscription_deleted.update_failed", logger.ErrorField(err), logger.String("subscription_id", subID))
		} else {
			logger.LogInfo("stripe.webhook.subscription_deleted.updated", logger.String("subscription_id", subID))
			h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
		}
	case "invoice.upcoming", "invoice.finalized", "invoice.voided", "invoice.marked_uncollectible":
		invoiceObj := event.Data.Object
		invoiceID, ok := invoiceObj["id"].(string)
		if !ok || invoiceID == "" {
			logger.LogError("stripe.webhook.invoice_event.missing_id", logger.String("type", string(event.Type)))
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
				logger.LogError("stripe.webhook.invoice_event.update_failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID), logger.String("status", status))
			} else {
				logger.LogInfo("stripe.webhook.invoice_event.updated", logger.String("invoice_id", invoiceID), logger.String("status", status))
				h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
			}
		}
	case "charge.refunded":
		chargeObj := event.Data.Object
		paymentID, ok := chargeObj["payment_intent"].(string)
		if !ok || paymentID == "" {
			logger.LogError("stripe.webhook.charge_refunded.missing_payment_intent")
			break
		}
		err := h.PaymentStore.UpdatePaymentStatus(c.Context(), paymentID, "refunded")
		if err != nil {
			logger.LogError("stripe.webhook.charge_refunded.update_failed", logger.ErrorField(err), logger.String("payment_id", paymentID))
		} else {
			logger.LogInfo("stripe.webhook.charge_refunded.updated", logger.String("payment_id", paymentID))
			h.Store.MarkStripeEventProcessed(c.Context(), event.ID, string(event.Type))
		}
	default:
		logger.LogInfo("stripe.webhook.unhandled_event", logger.String("type", string(event.Type)))
	}
	return c.SendStatus(fiber.StatusOK)
}

// swagger:route POST /billing-management/dunning/worker billing dunningWorker
// ---
// summary: Dunning worker
// description: Runs payment retries for failed invoices (internal use only).
// tags:
//   - billing
//   - dunning
//
// produces:
//   - application/json
//
// responses:
//
//	200:
//	  description: OK
//	  schema:
//	    type: string
func DunningWorker(store *PostgresStore, paymentStore payment.StoreInterface, accountService account.AccountService, notificationService security_management.NotificationService) {
	ctx := context.Background()
	logger.LogInfo("dunning.worker.starting")
	for {
		dunningConfig, err := store.GetDunningConfig(ctx, "") // pass tenantID if multi-tenant
		if err != nil || dunningConfig == nil {
			logger.LogError("dunning.worker.get_dunning_config_failed", logger.ErrorField(err))
			time.Sleep(5 * time.Minute)
			continue
		}
		invoices, err := store.ListInvoicesForDunning(ctx, time.Now().UTC(), dunningConfig.MaxAttempts)
		if err != nil {
			logger.LogError("dunning.worker.list_invoices_failed", logger.ErrorField(err))
			time.Sleep(5 * time.Minute)
			continue
		}
		for _, inv := range invoices {
			acct, err := accountService.GetAccount(inv.AccountID)
			if err != nil {
				logger.LogError("dunning.worker.account_not_found", logger.ErrorField(err), logger.String("account_id", inv.AccountID))
				continue
			}
			if acct.Email == "" {
				logger.LogError("dunning.worker.account_no_email", logger.String("account_id", inv.AccountID))
				continue
			}
			logger.LogInfo("dunning.worker.retrying_payment", logger.String("invoice_id", inv.ID), logger.String("account_id", inv.AccountID))
			failedPayment := &payment.FailedPayment{ID: inv.ID, InvoiceID: inv.ID, DunningAttempts: inv.DunningAttempts, DunningState: inv.DunningStatus, LastDunningAttempt: inv.DunningNextAttemptAt}
			result, payErr := payment.RetryPayment(ctx, paymentStore, failedPayment)
			if payErr == nil && result != nil && result.Status == "succeeded" {
				err := store.UpdateInvoiceStatus(ctx, inv.ID, "paid")
				if err != nil {
					logger.LogError("dunning.worker.update_invoice_status_failed", logger.ErrorField(err), logger.String("invoice_id", inv.ID))
				}
				details := map[string]interface{}{
					"invoice_id":    inv.ID,
					"amount":        inv.Amount,
					"currency":      inv.Currency,
					"status":        "paid",
					"account_id":    acct.ID,
					"account_email": acct.Email,
				}
				nErr := notificationService.SendNotification(ctx, acct.TenantID, security_management.NotificationEmail, []string{acct.Email}, "invoice.paid", details, 3)
				if nErr != nil {
					logger.LogError("dunning.worker.notify_paid_failed", logger.ErrorField(nErr), logger.String("account_id", acct.ID))
				}
				logger.LogInfo("dunning.worker.payment_success", logger.String("invoice_id", inv.ID))
				continue
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
			nErr := notificationService.SendNotification(ctx, acct.TenantID, security_management.NotificationEmail, []string{acct.Email}, "invoice.payment_failed", details, 3)
			if nErr != nil {
				logger.LogError("dunning.worker.notify_failed_failed", logger.ErrorField(nErr), logger.String("account_id", acct.ID))
			}
			// Optionally: escalate after N failures, e.g. mark as "collections" or similar
		}
		time.Sleep(1 * time.Hour)
	}
}

func (h *BillingAdminHandler) DeleteInvoice(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "invoice", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteInvoice: id required", logger.String("id", id))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	err := h.InvoiceService.DeleteInvoice(id)
	if err != nil {
		if err.Error() == "no rows" || err.Error() == "invoice not found" {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invoice not found"})
		}
		logger.LogError("DeleteInvoice: failed", logger.ErrorField(err), logger.String("id", id))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(fiber.StatusNoContent)
}
