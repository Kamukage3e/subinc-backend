package payment

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/braintree-go/braintree-go"

	paypal "github.com/plutov/paypal/v4"
	stripe "github.com/stripe/stripe-go/v75"
	stripeAccount "github.com/stripe/stripe-go/v75/account"
	stripePaymentIntent "github.com/stripe/stripe-go/v75/paymentintent"
	stripeRefund "github.com/stripe/stripe-go/v75/refund"

	"github.com/gofiber/fiber/v2"
	rbac_management "github.com/subinc/subinc-backend/internal/admin/rbac-management"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// PaymentHandler is the handler for payment-related routes
type PaymentHandler struct {
	PaymentService       PaymentService
	RefundService        RefundService
	PaymentMethodService PaymentMethodService
	ManualRefundService  ManualRefundService

	RBACService      rbac_management.RBACService          // optional, may be nil
	RateLimitService security_management.RateLimitService // for distributed rate limiting
	ConfigService    *server_config.Service               // for fetching secrets, keys, and static configs from server-config
	Logger           logger.Logger                        // add logger for webhook and handler logging
	Notify           security_management.NotificationService
	StoreRegistry    StoreInterface
}

// NewPaymentHandler creates a new payment handler
func NewPaymentHandler(
	paymentService PaymentService,
	refundService RefundService,
	manualRefundService ManualRefundService,
	paymentMethodService PaymentMethodService,

	rbacService rbac_management.RBACService,
	rateLimitService security_management.RateLimitService,
	configService *server_config.Service,
	logger logger.Logger,
	notify security_management.NotificationService,
	storeRegistry StoreInterface,
) *PaymentHandler {
	return &PaymentHandler{
		PaymentService:       paymentService,
		RefundService:        refundService,
		PaymentMethodService: paymentMethodService,
		ManualRefundService:  manualRefundService,
		RBACService:          rbacService,
		RateLimitService:     rateLimitService,
		ConfigService:        configService,
		Logger:               logger,
		Notify:               notify,
		StoreRegistry:        storeRegistry,
	}
}

// CreatePayment handles payment creation
func (h *PaymentHandler) CreatePayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	payment, err := h.PaymentService.CreatePayment(input)
	if err != nil {
		logger.LogError("CreatePayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create payment"})
	}

	return c.Status(fiber.StatusCreated).JSON(payment)
}

// RefundPayment handles payment refund
func (h *PaymentHandler) RefundPayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "refund")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input RefundPaymentRequest
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("RefundPayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	result, err := h.PaymentService.RefundPayment(c.Context(), &input)
	if err != nil {
		logger.LogError("RefundPayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to refund payment"})
	}

	return c.JSON(result)
}

// GetPaymentStatus handles payment status retrieval
func (h *PaymentHandler) GetPaymentStatus(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	paymentID := c.Query("payment_id")
	if paymentID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "payment_id is required"})
	}

	status, err := h.PaymentService.GetPaymentStatus(c.Context(), paymentID)
	if err != nil {
		logger.LogError("GetPaymentStatus: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment status"})
	}

	return c.JSON(status)
}

// UpdatePayment handles payment update
func (h *PaymentHandler) UpdatePayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	payment, err := h.PaymentService.UpdatePayment(input)
	if err != nil {
		logger.LogError("UpdatePayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update payment"})
	}

	return c.JSON(payment)
}

// GetPayment handles payment retrieval
func (h *PaymentHandler) GetPayment(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	payment, err := h.PaymentService.GetPayment(id)
	if err != nil {
		logger.LogError("GetPayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment"})
	}

	return c.JSON(payment)
}

// ListPayments handles payment listing
func (h *PaymentHandler) ListPayments(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	invoiceID := c.Query("invoice_id")
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "20"))

	payments, err := h.PaymentService.ListPayments(invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("ListPayments: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list payments"})
	}

	return c.JSON(fiber.Map{"payments": payments, "page": page, "page_size": pageSize})
}

// CreatePaymentMethod handles payment method creation
func (h *PaymentHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input struct {
		PaymentMethod PaymentMethod     `json:"payment_method"`
		PaymentData   map[string]string `json:"payment_data"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	method, err := h.PaymentMethodService.CreatePaymentMethod(input.PaymentMethod, input.PaymentData)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create payment method"})
	}

	return c.Status(fiber.StatusCreated).JSON(method)
}

// UpdatePaymentMethod handles payment method update
func (h *PaymentHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	method, err := h.PaymentMethodService.UpdatePaymentMethod(input)
	if err != nil {
		logger.LogError("UpdatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update payment method"})
	}

	return c.JSON(method)
}

// PatchPaymentMethod handles payment method patching
func (h *PaymentHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "patch")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input struct {
		ID         string `json:"id"`
		SetDefault *bool  `json:"set_default"`
		Status     string `json:"status"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("PatchPaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	if input.ID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	if err := h.PaymentMethodService.PatchPaymentMethod(input.ID, input.SetDefault, input.Status); err != nil {
		logger.LogError("PatchPaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to patch payment method"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// DeletePaymentMethod handles payment method deletion
func (h *PaymentHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	if err := h.PaymentMethodService.DeletePaymentMethod(id); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete payment method"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// GetPaymentMethod handles payment method retrieval
func (h *PaymentHandler) GetPaymentMethod(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	method, err := h.PaymentMethodService.GetPaymentMethod(id)
	if err != nil {
		logger.LogError("GetPaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment method"})
	}

	return c.JSON(method)
}

// ListPaymentMethods handles payment method listing
func (h *PaymentHandler) ListPaymentMethods(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "payment_method", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	accountID := c.Query("account_id")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "20"))

	methods, err := h.PaymentMethodService.ListPaymentMethods(accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListPaymentMethods: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list payment methods"})
	}

	return c.JSON(fiber.Map{"payment_methods": methods, "page": page, "page_size": pageSize})
}

// CreateRefund handles refund creation
func (h *PaymentHandler) CreateRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "create")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	refund, err := h.RefundService.CreateRefund(input)
	if err != nil {
		logger.LogError("CreateRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create refund"})
	}

	return c.Status(fiber.StatusCreated).JSON(refund)
}

// UpdateRefund handles refund update
func (h *PaymentHandler) UpdateRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "update")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	if err := h.RefundService.UpdateRefund(id); err != nil {
		logger.LogError("UpdateRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update refund"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteRefund handles refund deletion
func (h *PaymentHandler) DeleteRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "delete")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	if err := h.RefundService.DeleteRefund(id); err != nil {
		logger.LogError("DeleteRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete refund"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// GetRefund handles refund retrieval
func (h *PaymentHandler) GetRefund(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "read")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}

	refund, err := h.RefundService.GetRefund(id)
	if err != nil {
		logger.LogError("GetRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get refund"})
	}

	return c.JSON(refund)
}

// ListRefunds handles refund listing
func (h *PaymentHandler) ListRefunds(c *fiber.Ctx) error {
	if h.RBACService != nil {
		actorID := commonutil.GetActorID(c)
		permitted, err := h.RBACService.CheckPermission(c.Context(), actorID, "refund", "list")
		if err != nil || !permitted {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "permission denied"})
		}
	}

	paymentID := c.Query("payment_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize, _ := strconv.Atoi(c.Query("page_size", "20"))

	refunds, err := h.RefundService.ListRefunds(paymentID, invoiceID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListRefunds: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list refunds"})
	}

	return c.JSON(fiber.Map{"refunds": refunds, "page": page, "page_size": pageSize})
}

func MarshalAuditDetails(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (p *PaypalProvider) CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("paypal.create_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("paypal.create_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("paypal.create_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.Source == "" {
		err := errors.New("source must not be empty")
		logger.LogError("paypal.create_payment.missing_source", logger.ErrorField(err))
		return nil, err
	}
	if req.Source == PaymentMethodCard || req.Source == "visa" || req.Source == "mastercard" {
		err := errors.New("Direct card payments (visa/mastercard) not supported by PayPal Go SDK, use PayPal JS SDK on client")
		logger.LogError("paypal.create_payment.unsupported_card", logger.ErrorField(err), logger.String("source", req.Source))

		return nil, err
	}
	if req.Source == PaymentMethodApplePay {
		err := errors.New("Direct Apple Pay not supported by PayPal Go SDK, use PayPal JS SDK on client")
		logger.LogError("paypal.create_payment.unsupported_apple_pay", logger.ErrorField(err), logger.String("source", req.Source))

		return nil, err
	}
	if req.Source == PaymentMethodGooglePay {
		err := errors.New("Direct Google Pay not supported by PayPal Go SDK, use PayPal JS SDK on client")
		logger.LogError("paypal.create_payment.unsupported_google_pay", logger.ErrorField(err), logger.String("source", req.Source))

		return nil, err
	}
	if req.Source != "paypal" {
		err := errors.New("Unknown or unsupported payment source for PayPal")
		logger.LogError("paypal.create_payment.unsupported_source", logger.ErrorField(err), logger.String("source", req.Source))

		return nil, err
	}
	if p.Client == nil {
		err := errors.New("paypal client not initialized")
		logger.LogError("paypal.create_payment.client_not_initialized", logger.ErrorField(err))
		return nil, err
	}
	order, err := p.Client.CreateOrder(ctx, paypal.OrderIntentCapture, []paypal.PurchaseUnitRequest{{
		Amount: &paypal.PurchaseUnitAmount{
			Currency: req.Currency,
			Value:    formatAmount(req.Amount),
		},
		Description: req.Description,
	}}, nil, nil)
	if err != nil {
		logger.LogError("paypal.create_payment.create_order_failed", logger.ErrorField(err), logger.String("currency", req.Currency), logger.Float64("amount", req.Amount))
		return nil, errors.New("paypal: failed to create order")
	}
	if order.Status != "CREATED" && order.Status != "APPROVED" {
		err := errors.New("paypal: order not approved")
		logger.LogError("paypal.create_payment.order_not_approved", logger.ErrorField(err), logger.String("order_id", order.ID))
		return nil, err
	}
	capture, err := p.Client.CaptureOrder(ctx, order.ID, paypal.CaptureOrderRequest{})
	if err != nil {
		logger.LogError("paypal.create_payment.capture_failed", logger.ErrorField(err), logger.String("order_id", order.ID))
		return nil, errors.New("paypal: failed to capture order")
	}
	if len(capture.PurchaseUnits) == 0 || len(capture.PurchaseUnits[0].Payments.Captures) == 0 {
		err := errors.New("paypal: no capture found")
		logger.LogError("paypal.create_payment.no_capture", logger.ErrorField(err), logger.String("order_id", order.ID))
		return nil, err
	}
	cap := capture.PurchaseUnits[0].Payments.Captures[0]
	amount, _ := strconv.ParseFloat(cap.Amount.Value, 64)
	logger.LogInfo("paypal.create_payment.success", logger.String("capture_id", cap.ID), logger.Float64("amount", amount), logger.String("currency", cap.Amount.Currency))

	result := &PaymentResult{
		PaymentID: cap.ID,
		Status:    cap.Status,
		Amount:    amount,
		Currency:  cap.Amount.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "paypal",
		Raw:       capture,
	}
	if err := p.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("paypal.create_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (p *PaypalProvider) RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("paypal.refund_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("paypal.refund_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("paypal.refund_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.PaymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("paypal.refund_payment.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	if p.Client == nil {
		err := errors.New("paypal client not initialized")
		logger.LogError("paypal.refund_payment.client_not_initialized", logger.ErrorField(err))
		return nil, err
	}
	refund, err := p.Client.RefundCapture(ctx, req.PaymentID, paypal.RefundCaptureRequest{
		Amount: &paypal.Money{
			Currency: req.Currency,
			Value:    formatAmount(req.Amount),
		},
	})
	if err != nil {
		logger.LogError("paypal.refund_payment.failed", logger.ErrorField(err), logger.String("payment_id", req.PaymentID))
		return nil, errors.New("paypal: failed to refund payment")
	}
	amount, _ := strconv.ParseFloat(refund.Amount.Value, 64)
	logger.LogInfo("paypal.refund_payment.success", logger.String("refund_id", refund.ID), logger.Float64("amount", amount), logger.String("currency", refund.Amount.Currency))

	result := &PaymentResult{
		PaymentID: req.PaymentID,
		Status:    refund.Status,
		Amount:    amount,
		Currency:  refund.Amount.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "paypal",
		Raw:       refund,
	}
	if err := p.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("paypal.refund_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (p *PaypalProvider) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	if paymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("paypal.get_payment_status.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	result, err := p.Store.GetPaymentResult(ctx, paymentID)
	if err != nil {
		logger.LogError("paypal.get_payment_status.get_payment_failed", logger.ErrorField(err))

		return nil, err
	}

	return &PaymentStatus{
		PaymentID: result.PaymentID,
		Status:    result.Status,
		Amount:    result.Amount,
		Currency:  result.Currency,
		UpdatedAt: result.CreatedAt,
		Provider:  result.Provider,
		Raw:       result.Raw,
	}, nil
}

func (s *StripeProvider) CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("stripe.create_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("stripe.create_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("stripe.create_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.Source == "" {
		err := errors.New("source must not be empty")
		logger.LogError("stripe.create_payment.missing_source", logger.ErrorField(err))
		return nil, err
	}
	if s.APIKey == "" {
		err := errors.New("stripe api_key not initialized")
		logger.LogError("stripe.create_payment.api_key_missing", logger.ErrorField(err))
		return nil, err
	}
	stripe.Key = s.APIKey
	params := &stripe.PaymentIntentParams{
		Amount:      stripe.Int64(int64(req.Amount * 100)),
		Currency:    stripe.String(req.Currency),
		Confirm:     stripe.Bool(true),
		Description: stripe.String(req.Description),
	}
	switch req.Source {
	case PaymentMethodCard, "visa", "mastercard":
		params.PaymentMethodTypes = []*string{stripe.String("card")}
		params.PaymentMethod = stripe.String(req.Metadata["payment_method_id"])
	case PaymentMethodApplePay:
		params.PaymentMethodTypes = []*string{stripe.String("card")}
		params.PaymentMethod = stripe.String(req.Metadata["payment_method_id"])
		params.Metadata = map[string]string{"wallet": "apple_pay"}
	case PaymentMethodGooglePay:
		params.PaymentMethodTypes = []*string{stripe.String("card")}
		params.PaymentMethod = stripe.String(req.Metadata["payment_method_id"])
		params.Metadata = map[string]string{"wallet": "google_pay"}
	default:
		err := errors.New("unsupported payment method for Stripe")
		logger.LogError("stripe.create_payment.unsupported_method", logger.ErrorField(err), logger.String("source", req.Source))

		return nil, err
	}
	if req.Metadata != nil && params.Metadata == nil {
		params.Metadata = req.Metadata
	}
	intent, err := stripePaymentIntent.New(params)
	if err != nil {
		logger.LogError("stripe.create_payment.failed", logger.ErrorField(err), logger.String("currency", req.Currency), logger.Float64("amount", req.Amount))
		return nil, errors.New("stripe: failed to create payment intent")
	}
	logger.LogInfo("stripe.create_payment.success", logger.String("intent_id", intent.ID), logger.Float64("amount", float64(intent.Amount)/100.0), logger.String("currency", string(intent.Currency)))

	result := &PaymentResult{
		PaymentID: intent.ID,
		Status:    string(intent.Status),
		Amount:    float64(intent.Amount) / 100.0,
		Currency:  string(intent.Currency),
		CreatedAt: time.Unix(intent.Created, 0),
		Provider:  "stripe",
		Raw:       intent,
	}
	if err := s.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("stripe.create_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (s *StripeProvider) RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("stripe.refund_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("stripe.refund_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("stripe.refund_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.PaymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("stripe.refund_payment.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	if s.APIKey == "" {
		err := errors.New("stripe api_key not initialized")
		logger.LogError("stripe.refund_payment.api_key_missing", logger.ErrorField(err))
		return nil, err
	}
	stripe.Key = s.APIKey
	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(req.PaymentID),
		Amount:        stripe.Int64(int64(req.Amount * 100)),
	}
	refund, err := stripeRefund.New(params)
	if err != nil {
		logger.LogError("stripe.refund_payment.failed", logger.ErrorField(err), logger.String("payment_id", req.PaymentID))
		return nil, errors.New("stripe: failed to refund payment")
	}
	logger.LogInfo("stripe.refund_payment.success", logger.String("refund_id", refund.ID), logger.Float64("amount", float64(refund.Amount)/100.0), logger.String("currency", string(refund.Currency)))

	result := &PaymentResult{
		PaymentID: req.PaymentID,
		Status:    string(refund.Status),
		Amount:    float64(refund.Amount) / 100.0,
		Currency:  string(refund.Currency),
		CreatedAt: time.Unix(refund.Created, 0),
		Provider:  "stripe",
		Raw:       refund,
	}
	if err := s.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("stripe.refund_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (s *StripeProvider) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	if paymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("stripe.get_payment_status.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	result, err := s.Store.GetPaymentResult(ctx, paymentID)
	if err != nil {
		logger.LogError("stripe.get_payment_status.get_payment_failed", logger.ErrorField(err))

		return nil, err
	}

	return &PaymentStatus{
		PaymentID: result.PaymentID,
		Status:    result.Status,
		Amount:    result.Amount,
		Currency:  result.Currency,
		UpdatedAt: result.CreatedAt,
		Provider:  result.Provider,
		Raw:       result.Raw,
	}, nil
}

func formatAmount(amount float64) string {
	return strconv.FormatFloat(amount, 'f', 2, 64)
}

// Register adds a provider to the registry.
func (r *ProviderRegistry) Register(name string, provider PaymentProvider) {
	if r.providers == nil {
		r.providers = make(map[string]PaymentProvider)
	}
	r.providers[name] = provider
}

// Lookup returns a provider by name.
func (r *ProviderRegistry) Lookup(name string) (PaymentProvider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

// GetProviderForTenant loads the provider name and config for a tenant, instantiates the provider, and returns it
// store: payment.Store instance
// tenantID: the tenant to look up
// auditLogger: for audit logging
// configService: for fetching global provider config
func GetProviderForTenant(ctx context.Context, store StoreInterface, tenantID string, auditLogger security_management.AuditLogger, configService *server_config.Service) (PaymentProvider, error) {
	cfg, err := store.GetTenantPaymentProviderConfig(ctx, tenantID)
	if err != nil {
		logger.LogError("GetProviderForTenant: failed to get tenant config", logger.ErrorField(err))
		return nil, err
	}
	ownerCfg, err := configService.GetOwnerPaymentProviderConfig(ctx)
	if err != nil {
		logger.LogError("GetProviderForTenant: failed to get owner config", logger.ErrorField(err))
		return nil, err
	}
	secret, _ := store.GetTenantProviderSecret(ctx, tenantID, cfg.Provider)
	if secret == nil {
		secret = map[string]string{}
	}
	switch cfg.Provider {
	case "stripe":
		apiKey := ownerCfg.StripeAPIKey
		if v, ok := secret["api_key"]; ok && v != "" {
			apiKey = v
		}
		if apiKey == "" {
			logger.LogError("GetProviderForTenant: stripe api_key missing", logger.String("tenant_id", tenantID))
			return nil, errors.New("stripe api_key missing for tenant and owner")
		}
		return &StripeProvider{APIKey: apiKey, AuditLogger: auditLogger, Store: store}, nil
	case "paypal":
		clientID := ownerCfg.PaypalClientID
		clientSecret := ownerCfg.PaypalClientSecret
		if v, ok := secret["client_id"]; ok && v != "" {
			clientID = v
		}
		if v, ok := secret["client_secret"]; ok && v != "" {
			clientSecret = v
		}
		env := secret["env"]
		if clientID == "" || clientSecret == "" || env == "" {
			logger.LogError("GetProviderForTenant: paypal config missing", logger.String("tenant_id", tenantID))
			return nil, errors.New("paypal client_id, client_secret, or env missing for tenant and owner")
		}
		var apiBase string
		switch env {
		case "sandbox":
			apiBase = paypal.APIBaseSandBox
		case "live":
			apiBase = paypal.APIBaseLive
		default:
			logger.LogError("GetProviderForTenant: invalid paypal env", logger.String("env", env))
			return nil, errors.New("invalid paypal env")
		}
		client, err := paypal.NewClient(clientID, clientSecret, apiBase)
		if err != nil {
			logger.LogError("GetProviderForTenant: paypal client init failed", logger.ErrorField(err))
			return nil, err
		}
		return &PaypalProvider{Client: client, AuditLogger: auditLogger, Store: store}, nil
	case "braintree":
		merchantID := ownerCfg.BraintreeMerchantID
		publicKey := ownerCfg.BraintreePublicKey
		privateKey := ownerCfg.BraintreePrivateKey
		env := ownerCfg.BraintreeEnv
		if v, ok := secret["merchant_id"]; ok && v != "" {
			merchantID = v
		}
		if v, ok := secret["public_key"]; ok && v != "" {
			publicKey = v
		}
		if v, ok := secret["private_key"]; ok && v != "" {
			privateKey = v
		}
		if v, ok := secret["env"]; ok && v != "" {
			env = v
		}
		if merchantID == "" || publicKey == "" || privateKey == "" || env == "" {
			logger.LogError("GetProviderForTenant: braintree config missing", logger.String("tenant_id", tenantID))
			return nil, errors.New("braintree merchant_id, public_key, private_key, or env missing for tenant and owner")
		}
		var btEnv braintree.Environment
		switch env {
		case "sandbox":
			btEnv = braintree.Sandbox
		case "production":
			btEnv = braintree.Production
		default:
			logger.LogError("GetProviderForTenant: invalid braintree env", logger.String("env", env))
			return nil, errors.New("invalid braintree env")
		}
		client := braintree.New(btEnv, merchantID, publicKey, privateKey)
		_, err = client.Transaction().Search(ctx, &braintree.SearchQuery{})
		return &BraintreeProvider{Client: client, AuditLogger: auditLogger, Store: store}, nil
	default:
		logger.LogError("GetProviderForTenant: unsupported provider", logger.String("provider", cfg.Provider))
		return nil, errors.New("unsupported provider: " + cfg.Provider)
	}
}



func CheckProviderConnection(ctx context.Context, store StoreInterface, tenantID, providerName string, configService *server_config.Service) error {
	err := error(nil)

	var ownerCfg server_config.PaymentProviderConfig
	if configService != nil {
		ownerCfg, _ = configService.GetOwnerPaymentProviderConfig(ctx)
	}
	switch providerName {
	case "stripe":
		apiKey := ownerCfg.StripeAPIKey
		secret, err2 := store.GetTenantProviderSecret(ctx, tenantID, "stripe")
		if err2 == nil {
			if v, ok := secret["api_key"]; ok && v != "" {
				apiKey = v
			}
		}
		if apiKey == "" {
			err = errors.New("stripe api_key missing for tenant and owner")
			break
		}
		stripe.Key = apiKey
		_, err = stripeAccount.Get()
	case "paypal":
		clientID := ownerCfg.PaypalClientID
		clientSecret := ownerCfg.PaypalClientSecret
		secret, err2 := store.GetTenantProviderSecret(ctx, tenantID, "paypal")
		if err2 == nil {
			if v, ok := secret["client_id"]; ok && v != "" {
				clientID = v
			}
			if v, ok := secret["client_secret"]; ok && v != "" {
				clientSecret = v
			}
		}
		env := secret["env"]
		if clientID == "" || clientSecret == "" || env == "" {
			err = errors.New("paypal client_id, client_secret, or env missing for tenant and owner")
			break
		}
		var apiBase string
		switch env {
		case "sandbox":
			apiBase = paypal.APIBaseSandBox
		case "live":
			apiBase = paypal.APIBaseLive
		default:
			err = errors.New("invalid paypal env")
			break
		}
		client, err2 := paypal.NewClient(clientID, clientSecret, apiBase)
		if err2 != nil {
			err = err2
			break
		}
		_, err = client.GetAccessToken(ctx)
	case "braintree":
		merchantID := ownerCfg.BraintreeMerchantID
		publicKey := ownerCfg.BraintreePublicKey
		privateKey := ownerCfg.BraintreePrivateKey
		env := ownerCfg.BraintreeEnv
		secret, err2 := store.GetTenantProviderSecret(ctx, tenantID, "braintree")
		if err2 == nil {
			if v, ok := secret["merchant_id"]; ok && v != "" {
				merchantID = v
			}
			if v, ok := secret["public_key"]; ok && v != "" {
				publicKey = v
			}
			if v, ok := secret["private_key"]; ok && v != "" {
				privateKey = v
			}
			if v, ok := secret["env"]; ok && v != "" {
				env = v
			}
		}
		if merchantID == "" || publicKey == "" || privateKey == "" || env == "" {
			err = errors.New("braintree merchant_id, public_key, private_key, or env missing for tenant and owner")
			break
		}
		var btEnv braintree.Environment
		switch env {
		case "sandbox":
			btEnv = braintree.Sandbox
		case "production":
			btEnv = braintree.Production
		default:
			err = errors.New("invalid braintree env")
			break
		}
		client := braintree.New(btEnv, merchantID, publicKey, privateKey)
		_, err = client.Transaction().Search(ctx, &braintree.SearchQuery{})
	default:
		err = errors.New("unsupported provider: " + providerName)
	}

	return err
}

func RetryPayment(ctx context.Context, store StoreInterface, p interface{}) (*PaymentResult, error) {
	failed, ok := p.(*FailedPayment)
	if !ok || failed == nil {
		logger.LogError("RetryPayment: invalid payment type", logger.ErrorField(errors.New("invalid payment type")))
		return nil, errors.New("invalid payment type")
	}
	pay, err := store.GetPaymentResult(ctx, failed.ID)
	if err != nil {
		logger.LogError("RetryPayment: failed to load payment", logger.ErrorField(err))
		return nil, err
	}
	cfg, err := store.GetTenantPaymentProviderConfig(ctx, pay.Provider)
	if err != nil {
		logger.LogError("RetryPayment: failed to load provider config", logger.ErrorField(err))
		return nil, err
	}
	provider, err := GetProviderForTenant(ctx, store, cfg.TenantID, nil, nil)
	if err != nil {
		logger.LogError("RetryPayment: failed to get provider", logger.ErrorField(err))
		return nil, err
	}
	// Reconstruct CreatePaymentRequest from original payment (assume Raw has enough info)
	var req *CreatePaymentRequest
	if pay.Raw != nil {
		b, _ := json.Marshal(pay.Raw)
		_ = json.Unmarshal(b, &req)
	}
	if req == nil {
		req = &CreatePaymentRequest{
			Amount:      pay.Amount,
			Currency:    pay.Currency,
			Source:      "", // Can't retry without source, must be in Raw or metadata
			Description: "Retry payment",
			Metadata:    map[string]string{"retry": "true"},
		}
	}
	if req.Source == "" && pay.Raw != nil {
		if m, ok := pay.Raw.(map[string]interface{}); ok {
			if s, ok := m["source"].(string); ok {
				req.Source = s
			}
		}
	}
	if req.Source == "" {
		logger.LogError("RetryPayment: missing source, cannot retry", logger.ErrorField(errors.New("missing source")))
		return nil, errors.New("missing source for retry")
	}
	result, err := provider.CreatePayment(ctx, req)
	if err != nil {
		logger.LogError("RetryPayment: payment retry failed", logger.ErrorField(err))
		// Audit log failure

		return &PaymentResult{PaymentID: pay.PaymentID, Status: "failed", Amount: pay.Amount, Currency: pay.Currency, CreatedAt: time.Now().UTC(), Provider: pay.Provider}, err
	}
	// Audit log success
	return result, nil
}

func (b *BraintreeProvider) CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("braintree.create_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("braintree.create_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("braintree.create_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.Source == "" {
		err := errors.New("source must not be empty")
		logger.LogError("braintree.create_payment.missing_source", logger.ErrorField(err))
		return nil, err
	}
	if b.Client == nil {
		err := errors.New("braintree client not initialized")
		logger.LogError("braintree.create_payment.client_not_initialized", logger.ErrorField(err))
		return nil, err
	}
	btReq := &braintree.TransactionRequest{
		Type:               "sale",
		Amount:             braintree.NewDecimal(int64(req.Amount*100), 2),
		PaymentMethodNonce: req.Source,
		Options: &braintree.TransactionOptions{
			SubmitForSettlement: true,
		},
		OrderId:      req.Metadata["order_id"],
		CustomFields: req.Metadata,
	}
	tr, err := b.Client.Transaction().Create(ctx, btReq)
	if err != nil {
		logger.LogError("braintree.create_payment.failed", logger.ErrorField(err))
		return nil, errors.New("braintree: failed to create transaction")
	}
	result := &PaymentResult{
		PaymentID: tr.Id,
		Status:    string(tr.Status),
		Amount:    req.Amount,
		Currency:  req.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "braintree",
		Raw:       tr,
	}
	if err := b.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("braintree.create_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (b *BraintreeProvider) RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error) {
	if req == nil {
		err := errors.New("request must not be nil")
		logger.LogError("braintree.refund_payment.invalid_request", logger.ErrorField(err))
		return nil, err
	}
	if req.Amount <= 0 {
		err := errors.New("amount must be positive")
		logger.LogError("braintree.refund_payment.invalid_amount", logger.ErrorField(err))
		return nil, err
	}
	if req.Currency == "" {
		err := errors.New("currency must not be empty")
		logger.LogError("braintree.refund_payment.missing_currency", logger.ErrorField(err))
		return nil, err
	}
	if req.PaymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("braintree.refund_payment.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	if b.Client == nil {
		err := errors.New("braintree client not initialized")
		logger.LogError("braintree.refund_payment.client_not_initialized", logger.ErrorField(err))
		return nil, err
	}
	tr, err := b.Client.Transaction().Refund(ctx, req.PaymentID)
	if err != nil {
		logger.LogError("braintree.refund_payment.failed", logger.ErrorField(err), logger.String("payment_id", req.PaymentID))
		return nil, errors.New("braintree: failed to refund transaction")
	}
	amount := req.Amount
	if tr.Amount != nil {
		amount = float64(tr.Amount.Unscaled) / 100
	}
	result := &PaymentResult{
		PaymentID: tr.Id,
		Status:    string(tr.Status),
		Amount:    amount,
		Currency:  req.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "braintree",
		Raw:       tr,
	}
	if err := b.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("braintree.refund_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	return result, nil
}

func (b *BraintreeProvider) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	if paymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("braintree.get_payment_status.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	if b.Client == nil {
		err := errors.New("braintree client not initialized")
		logger.LogError("braintree.get_payment_status.client_not_initialized", logger.ErrorField(err))
		return nil, err
	}
	tr, err := b.Client.Transaction().Find(ctx, paymentID)
	if err != nil {
		logger.LogError("braintree.get_payment_status.find_failed", logger.ErrorField(err))
		return nil, errors.New("braintree: failed to find transaction")
	}
	amount := 0.0
	if tr.Amount != nil {
		amount = float64(tr.Amount.Unscaled) / 100
	}
	return &PaymentStatus{
		PaymentID: tr.Id,
		Status:    string(tr.Status),
		Amount:    amount,
		Currency:  tr.CurrencyISOCode,
		UpdatedAt: time.Now().UTC(),
		Provider:  "braintree",
		Raw:       tr,
	}, nil
}
