package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"strconv"
	"time"

	"github.com/braintree-go/braintree-go"

	paypal "github.com/plutov/paypal/v4"
	stripe "github.com/stripe/stripe-go/v75"
	stripeAccount "github.com/stripe/stripe-go/v75/account"
	"github.com/stripe/stripe-go/v75/paymentintent"
	"github.com/stripe/stripe-go/v75/refund"

	"github.com/gofiber/fiber/v2"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// PaymentHandler handles payment-related operations
type PaymentHandler struct {
	PaymentService       PaymentService
	RefundService        RefundService
	PaymentMethodService PaymentMethodService
	ManualRefundService  ManualRefundService
	DisputeService       DisputeDataStoreInterface // For dispute management
	EvidenceService      DisputeDataStoreInterface // For dispute evidence management
	Store                StoreInterface
	RateLimitService     security_management.RateLimitService
	ConfigService        *server_config.Service
	Logger               logger.Logger
	Notify               security_management.NotificationService
}

// NewPaymentHandler creates a new payment handler
func NewPaymentHandler(
	paymentService PaymentService,
	refundService RefundService,
	manualRefundService ManualRefundService,
	paymentMethodService PaymentMethodService,
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
		RateLimitService:     rateLimitService,
		ConfigService:        configService,
		Logger:               logger,
		Notify:               notify,
		Store:                storeRegistry,
	}
}

// CreatePayment handles payment creation
func (h *PaymentHandler) CreatePayment(c *fiber.Ctx) error {
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	payment, err := h.PaymentService.CreatePayment(c.Context(), input)
	if err != nil {
		logger.LogError("CreatePayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create payment"})
	}
	return c.Status(fiber.StatusCreated).JSON(payment)
}

// RefundPayment handles payment refund
func (h *PaymentHandler) RefundPayment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("RefundPayment: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input RefundPaymentRequest
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("RefundPayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.PaymentID = id
	result, err := h.PaymentService.RefundPayment(c.Context(), &input)
	if err != nil {
		logger.LogError("RefundPayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to refund payment"})
	}
	return c.JSON(result)
}

// GetPaymentStatus handles payment status retrieval
func (h *PaymentHandler) GetPaymentStatus(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPaymentStatus: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	status, err := h.PaymentService.GetPaymentStatus(c.Context(), id)
	if err != nil {
		logger.LogError("GetPaymentStatus: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment status"})
	}
	return c.JSON(status)
}

// UpdatePayment handles payment update
func (h *PaymentHandler) UpdatePayment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdatePayment: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input Payment
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePayment: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	payment, err := h.PaymentService.UpdatePayment(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update payment"})
	}
	return c.JSON(payment)
}

// GetPayment handles payment retrieval
func (h *PaymentHandler) GetPayment(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPayment: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	payment, err := h.PaymentService.GetPayment(c.Context(), id)
	if err != nil {
		logger.LogError("GetPayment: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment"})
	}
	return c.JSON(payment)
}

// ListPayments handles payment listing
func (h *PaymentHandler) ListPayments(c *fiber.Ctx) error {
	invoiceID := c.Query("invoice_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 20)
	payments, err := h.PaymentService.ListPayments(c.Context(), invoiceID, page, pageSize)
	if err != nil {
		logger.LogError("ListPayments: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list payments"})
	}
	return c.JSON(fiber.Map{"payments": payments, "page": page, "page_size": pageSize})
}

// CreatePaymentMethod handles payment method creation
func (h *PaymentHandler) CreatePaymentMethod(c *fiber.Ctx) error {
	var input struct {
		PaymentMethod PaymentMethod     `json:"payment_method"`
		PaymentData   map[string]string `json:"payment_data"`
	}

	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	method, err := h.PaymentMethodService.CreatePaymentMethod(c.Context(), input.PaymentMethod, input.PaymentData)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create payment method"})
	}

	return c.Status(fiber.StatusCreated).JSON(method)
}

// UpdatePaymentMethod handles payment method update
func (h *PaymentHandler) UpdatePaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdatePaymentMethod: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input PaymentMethod
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdatePaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.ID = id
	method, err := h.PaymentMethodService.UpdatePaymentMethod(c.Context(), input)
	if err != nil {
		logger.LogError("UpdatePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update payment method"})
	}
	return c.JSON(method)
}

// PatchPaymentMethod handles payment method patching
func (h *PaymentHandler) PatchPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("PatchPaymentMethod: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input struct {
		SetDefault *bool  `json:"set_default"`
		Status     string `json:"status"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("PatchPaymentMethod: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	err := h.PaymentMethodService.PatchPaymentMethod(c.Context(), id, input.SetDefault, input.Status)
	if err != nil {
		logger.LogError("PatchPaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to patch payment method"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DeletePaymentMethod handles payment method deletion
func (h *PaymentHandler) DeletePaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeletePaymentMethod: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	if err := h.PaymentMethodService.DeletePaymentMethod(c.Context(), id); err != nil {
		logger.LogError("DeletePaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete payment method"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GetPaymentMethod handles payment method retrieval
func (h *PaymentHandler) GetPaymentMethod(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetPaymentMethod: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	method, err := h.PaymentMethodService.GetPaymentMethod(c.Context(), id)
	if err != nil {
		logger.LogError("GetPaymentMethod: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get payment method"})
	}
	return c.JSON(method)
}

// ListPaymentMethods handles payment method listing
func (h *PaymentHandler) ListPaymentMethods(c *fiber.Ctx) error {
	accountID := c.Query("account_id")
	status := c.Query("status")
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil {
		logger.LogError("ListPaymentMethods: invalid page", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page"})
	}
	pageSize, err := strconv.Atoi(c.Query("page_size", "20"))
	if err != nil {
		logger.LogError("ListPaymentMethods: invalid page_size", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page_size"})
	}

	methods, err := h.PaymentMethodService.ListPaymentMethods(c.Context(), accountID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListPaymentMethods: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list payment methods"})
	}

	return c.JSON(fiber.Map{"payment_methods": methods, "page": page, "page_size": pageSize})
}

// CreateRefund handles refund creation
func (h *PaymentHandler) CreateRefund(c *fiber.Ctx) error {
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}

	refund, err := h.RefundService.CreateRefund(c.Context(), input)
	if err != nil {
		logger.LogError("CreateRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create refund"})
	}

	return c.Status(fiber.StatusCreated).JSON(refund)
}

// UpdateRefund handles refund update
func (h *PaymentHandler) UpdateRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateRefund: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input Refund
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	refund, err := h.RefundService.UpdateRefund(c.Context(), input)
	if err != nil {
		logger.LogError("UpdateRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update refund"})
	}
	return c.JSON(refund)
}

// DeleteRefund handles refund deletion
func (h *PaymentHandler) DeleteRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteRefund: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	if err := h.RefundService.DeleteRefund(c.Context(), id); err != nil {
		logger.LogError("DeleteRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete refund"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GetRefund handles refund retrieval
func (h *PaymentHandler) GetRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetRefund: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	refund, err := h.RefundService.GetRefund(c.Context(), id)
	if err != nil {
		logger.LogError("GetRefund: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get refund"})
	}
	return c.JSON(refund)
}

// ListRefunds handles refund listing
func (h *PaymentHandler) ListRefunds(c *fiber.Ctx) error {
	paymentID := c.Query("payment_id")
	invoiceID := c.Query("invoice_id")
	status := c.Query("status")
	page, err := strconv.Atoi(c.Query("page", "1"))
	if err != nil {
		logger.LogError("ListRefunds: invalid page", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page"})
	}
	pageSize, err := strconv.Atoi(c.Query("page_size", "20"))
	if err != nil {
		logger.LogError("ListRefunds: invalid page_size", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid page_size"})
	}

	refunds, err := h.RefundService.ListRefunds(c.Context(), paymentID, invoiceID, status, page, pageSize)
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
func GetProviderForTenant(ctx context.Context, store StoreInterface, tenantID string, configService *server_config.Service) (PaymentProvider, error) {
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
		return &StripeProvider{APIKey: apiKey, Store: store}, nil
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
		return &PaypalProvider{Client: client, Store: store}, nil
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
		if err != nil {
			logger.LogError("GetProviderForTenant: braintree client search failed", logger.ErrorField(err))
			return nil, err
		}
		return &BraintreeProvider{Client: client, Store: store}, nil
	default:
		logger.LogError("GetProviderForTenant: unsupported provider", logger.String("provider", cfg.Provider))
		return nil, errors.New("unsupported provider: " + cfg.Provider)
	}
}

func CheckProviderConnection(ctx context.Context, store StoreInterface, tenantID, providerName string, configService *server_config.Service) error {
	var err error

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
			logger.LogError("CheckProviderConnection: stripe api_key missing", logger.ErrorField(err))
			break
		}
		stripe.Key = apiKey
		_, err = stripeAccount.Get()
		if err != nil {
			logger.LogError("CheckProviderConnection: stripe account get failed", logger.ErrorField(err))
		}
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
			logger.LogError("CheckProviderConnection: paypal config missing", logger.ErrorField(err))
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
			logger.LogError("CheckProviderConnection: invalid paypal env", logger.ErrorField(err))
			break
		}
		client, err2 := paypal.NewClient(clientID, clientSecret, apiBase)
		if err2 != nil {
			err = err2
			logger.LogError("CheckProviderConnection: paypal client init failed", logger.ErrorField(err))
			break
		}
		_, err = client.GetAccessToken(ctx)
		if err != nil {
			logger.LogError("CheckProviderConnection: paypal get access token failed", logger.ErrorField(err))
		}
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
			logger.LogError("CheckProviderConnection: braintree config missing", logger.ErrorField(err))
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
			logger.LogError("CheckProviderConnection: invalid braintree env", logger.ErrorField(err))
			break
		}
		client := braintree.New(btEnv, merchantID, publicKey, privateKey)
		_, err = client.Transaction().Search(ctx, &braintree.SearchQuery{})
		if err != nil {
			logger.LogError("CheckProviderConnection: braintree transaction search failed", logger.ErrorField(err))
		}
	default:
		err = errors.New("unsupported provider: " + providerName)
		logger.LogError("CheckProviderConnection: unsupported provider", logger.ErrorField(err))
	}

	return err
}

func RetryPayment(ctx context.Context, store StoreInterface, p interface{}) (*PaymentResult, error) {
	failed, ok := p.(*FailedPayment)
	if !ok || failed == nil {
		err := errors.New("invalid payment type")
		logger.LogError("RetryPayment: invalid payment type", logger.ErrorField(err))
		return nil, err
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
	provider, err := GetProviderForTenant(ctx, store, cfg.TenantID, nil)
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
		err := errors.New("missing source for retry")
		logger.LogError("RetryPayment: missing source, cannot retry", logger.ErrorField(err))
		return nil, err
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

	// Check for idempotency key
	idempotencyKey := ""
	if req.Metadata != nil {
		idempotencyKey = req.Metadata["idempotency_key"]
	}

	// If idempotency key exists, check if we already processed this payment
	if idempotencyKey != "" {
		// Convert store to a PaymentService to access the GetPaymentByIdempotencyKey method
		if store, ok := s.Store.(interface {
			GetPaymentByIdempotencyKey(ctx context.Context, idempotencyKey string) (Payment, error)
		}); ok {
			existingPayment, err := store.GetPaymentByIdempotencyKey(ctx, idempotencyKey)
			if err != nil {
				logger.LogError("stripe.create_payment.idempotency_check_failed", logger.ErrorField(err), logger.String("idempotency_key", idempotencyKey))
				// Continue with payment creation even if idempotency check fails
			} else if existingPayment.ID != "" {
				// Payment with this idempotency key already exists, return stored result
				logger.LogInfo("stripe.create_payment.idempotent_match", logger.String("payment_id", existingPayment.ID), logger.String("idempotency_key", idempotencyKey))

				// Try to get the complete payment result
				result, err := s.Store.GetPaymentResult(ctx, existingPayment.ID)
				if err != nil {
					logger.LogError("stripe.create_payment.get_existing_result_failed", logger.ErrorField(err), logger.String("payment_id", existingPayment.ID))
					// Return a basic result constructed from the existingPayment
					return &PaymentResult{
						PaymentID: existingPayment.ID,
						Status:    existingPayment.Status,
						Amount:    existingPayment.Amount,
						Currency:  existingPayment.Currency,
						CreatedAt: existingPayment.CreatedAt,
						Provider:  "stripe",
					}, nil
				}

				return result, nil
			}
		}
	}

	stripe.Key = s.APIKey
	params := &stripe.PaymentIntentParams{
		Amount:      stripe.Int64(int64(req.Amount * 100)),
		Currency:    stripe.String(req.Currency),
		Confirm:     stripe.Bool(true),
		Description: stripe.String(req.Description),
	}

	// Add idempotency key to Stripe API params if available
	if idempotencyKey != "" {
		params.Params.IdempotencyKey = stripe.String(idempotencyKey)
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

	// Ensure we preserve all metadata, including idempotency key
	if req.Metadata != nil {
		if params.Metadata == nil {
			params.Metadata = req.Metadata
		} else {
			for k, v := range req.Metadata {
				params.Metadata[k] = v
			}
		}
	}

	intent, err := paymentintent.New(params)
	if err != nil {
		logger.LogError("stripe.create_payment.failed", logger.ErrorField(err), logger.String("currency", req.Currency), logger.Float64("amount", req.Amount))
		return nil, errors.New("stripe: failed to create payment intent")
	}

	logger.LogInfo("stripe.create_payment.success",
		logger.String("intent_id", intent.ID),
		logger.Float64("amount", float64(intent.Amount)/100.0),
		logger.String("currency", string(intent.Currency)),
		logger.String("idempotency_key", idempotencyKey))

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

	// Generate idempotency key if not provided (using payment_id + amount as a basis)
	idempotencyKey := fmt.Sprintf("refund_%s_%d", req.PaymentID, int64(req.Amount*100))

	stripe.Key = s.APIKey
	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(req.PaymentID),
		Amount:        stripe.Int64(int64(req.Amount * 100)),
		Params: stripe.Params{
			IdempotencyKey: stripe.String(idempotencyKey),
		},
	}

	// Add reason if provided
	if req.Reason != "" {
		params.Reason = stripe.String(req.Reason)
	}

	// Check if this refund was already processed
	// Look for payments with the same payment_id in refunded status
	existingResult, err := s.Store.GetPaymentResult(ctx, req.PaymentID)
	if err == nil && existingResult != nil && existingResult.Status == "refunded" {
		logger.LogInfo("stripe.refund_payment.already_refunded",
			logger.String("payment_id", req.PaymentID),
			logger.String("idempotency_key", idempotencyKey))
		return existingResult, nil
	}

	refund, err := refund.New(params)
	if err != nil {
		// Check if it's an idempotency error (refund already exists)
		if strErr, ok := err.(*stripe.Error); ok && strErr.Code == "idempotency_error" {
			logger.LogInfo("stripe.refund_payment.idempotency_error",
				logger.String("payment_id", req.PaymentID),
				logger.String("idempotency_key", idempotencyKey))

			// Try to fetch the original refund
			result := &PaymentResult{
				PaymentID: req.PaymentID,
				Status:    "refunded", // Assume refunded since we got an idempotency error
				Amount:    req.Amount,
				Currency:  req.Currency,
				CreatedAt: time.Now().UTC(),
				Provider:  "stripe",
			}
			return result, nil
		}

		logger.LogError("stripe.refund_payment.failed",
			logger.ErrorField(err),
			logger.String("payment_id", req.PaymentID))
		return nil, errors.New("stripe: failed to refund payment")
	}

	logger.LogInfo("stripe.refund_payment.success",
		logger.String("refund_id", refund.ID),
		logger.Float64("amount", float64(refund.Amount)/100.0),
		logger.String("currency", string(refund.Currency)),
		logger.String("idempotency_key", idempotencyKey))

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

	// Update the payment status to reflect the refund
	if err := s.Store.UpdatePaymentStatus(ctx, req.PaymentID, "refunded"); err != nil {
		logger.LogWarn("stripe.refund_payment.update_status_failed",
			logger.ErrorField(err),
			logger.String("payment_id", req.PaymentID))
		// Continue anyway since the refund was successful
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

func (h *PaymentHandler) CreateDispute(c *fiber.Ctx) error {
	var input Dispute
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateDispute: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if input.ID == "" {
		logger.LogError("CreateDispute: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "id required"})
	}
	if err := h.DisputeService.CreateDispute(c.Context(), &input); err != nil {
		logger.LogError("CreateDispute: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(input)
}

func (h *PaymentHandler) ListDisputes(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	paymentID := c.Query("payment_id")
	status := DisputeStatus(c.Query("status"))
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	if tenantID == "" {
		logger.LogError("ListDisputes: tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "tenant_id required"})
	}
	disputes, err := h.DisputeService.ListDisputes(c.Context(), tenantID, paymentID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListDisputes: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"disputes": disputes, "page": page, "page_size": pageSize})
}

func (h *PaymentHandler) GetDispute(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("GetDispute: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	dispute, err := h.DisputeService.GetDispute(c.Context(), id)
	if err != nil {
		logger.LogError("GetDispute: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(dispute)
}

func (h *PaymentHandler) UpdateDispute(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("UpdateDispute: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	var input struct {
		Status            DisputeStatus `json:"status"`
		EvidenceSubmitted *time.Time    `json:"evidence_submitted"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateDispute: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.DisputeService.UpdateDisputeStatus(c.Context(), id, input.Status, input.EvidenceSubmitted); err != nil {
		logger.LogError("UpdateDispute: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *PaymentHandler) DeleteDispute(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("DeleteDispute: id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id required"})
	}
	err := h.DisputeService.DeleteDispute(c.Context(), id)
	if err != nil {
		if err.Error() == "dispute not found" {
			logger.LogError("DeleteDispute: dispute not found", logger.ErrorField(err))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "dispute not found"})
		}
		logger.LogError("DeleteDispute: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete dispute"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *PaymentHandler) CreateEvidence(c *fiber.Ctx) error {
	disputeID := c.Params("id")
	if disputeID == "" {
		logger.LogError("CreateEvidence: dispute_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "dispute_id required"})
	}
	var input DisputeEvidence
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateEvidence: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	input.DisputeID = disputeID
	if err := h.EvidenceService.CreateDisputeEvidence(c.Context(), &input); err != nil {
		logger.LogError("CreateEvidence: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.Status(fiber.StatusCreated).JSON(input)
}

func (h *PaymentHandler) ListEvidence(c *fiber.Ctx) error {
	disputeID := c.Params("id")
	tenantID := c.Query("tenant_id")
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("page_size", 100)
	if disputeID == "" || tenantID == "" {
		logger.LogError("ListEvidence: dispute_id and tenant_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "dispute_id and tenant_id required"})
	}
	evidence, err := h.EvidenceService.ListDisputeEvidence(c.Context(), disputeID, tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListEvidence: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.JSON(fiber.Map{"evidence": evidence, "page": page, "page_size": pageSize})
}

func (h *PaymentHandler) GetEvidence(c *fiber.Ctx) error {
	evidenceID := c.Params("evidence_id")
	if evidenceID == "" {
		logger.LogError("GetEvidence: evidence_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "evidence_id required"})
	}
	evidence, err := h.EvidenceService.GetDisputeEvidence(c.Context(), evidenceID)
	if err != nil {
		logger.LogError("GetEvidence: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrNotFound)
	}
	return c.JSON(evidence)
}

func (h *PaymentHandler) UpdateEvidence(c *fiber.Ctx) error {
	evidenceID := c.Params("evidence_id")
	if evidenceID == "" {
		logger.LogError("UpdateEvidence: evidence_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "evidence_id required"})
	}
	var input struct {
		ProviderStatus   string `json:"provider_status"`
		ProviderResponse string `json:"provider_response"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("UpdateEvidence: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	if err := h.EvidenceService.UpdateDisputeEvidenceStatus(c.Context(), evidenceID, input.ProviderStatus, input.ProviderResponse); err != nil {
		logger.LogError("UpdateEvidence: failed", logger.ErrorField(err))
		return c.JSON(fiber.ErrExpectationFailed)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *PaymentHandler) DeleteEvidence(c *fiber.Ctx) error {
	evidenceID := c.Params("evidence_id")
	if evidenceID == "" {
		logger.LogError("DeleteEvidence: evidence_id required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "evidence_id required"})
	}
	err := h.EvidenceService.DeleteDisputeEvidence(c.Context(), evidenceID)
	if err != nil {
		if err.Error() == "dispute evidence not found" {
			logger.LogError("DeleteEvidence: dispute evidence not found", logger.ErrorField(err))
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "dispute evidence not found"})
		}
		logger.LogError("DeleteEvidence: failed", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete dispute evidence"})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Plugin management handlers

// ListPaymentPlugins returns all registered payment plugins
func (h *PaymentHandler) ListPaymentPlugins(c *fiber.Ctx) error {
	pluginNames := PaymentPlugins.List()
	return c.JSON(fiber.Map{
		"plugins": pluginNames,
	})
}

// GetTransactionReport handles transaction reporting requests for a specific time period
func (h *PaymentHandler) GetTransactionReport(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTransactionReport: tenant_id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}

	// Parse date parameters with defaults
	startStr := c.Query("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endStr := c.Query("end_date", time.Now().Format("2006-01-02"))
	includeDailyTotals := c.QueryBool("include_daily_totals", false)

	startDate, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		logger.LogError("GetTransactionReport: invalid start_date", logger.ErrorField(err), logger.String("start_date", startStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid start_date format, use YYYY-MM-DD"})
	}

	endDate, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		logger.LogError("GetTransactionReport: invalid end_date", logger.ErrorField(err), logger.String("end_date", endStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid end_date format, use YYYY-MM-DD"})
	}

	// Ensure end date is inclusive by extending to the end of the day
	endDate = endDate.Add(24*time.Hour - 1*time.Second)

	// Validate date range
	if startDate.After(endDate) {
		logger.LogError("GetTransactionReport: start_date after end_date", logger.String("start_date", startStr), logger.String("end_date", endStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "start_date must be before end_date"})
	}

	// Maximum report period is 1 year
	maxPeriod := 365 * 24 * time.Hour
	if endDate.Sub(startDate) > maxPeriod {
		logger.LogError("GetTransactionReport: date range exceeds maximum allowed period", logger.String("start_date", startStr), logger.String("end_date", endStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "date range exceeds maximum allowed period of 1 year",
		})
	}

	// Get the transaction report
	report, err := h.Store.GetTransactionReport(c.Context(), tenantID, startDate, endDate, includeDailyTotals)
	if err != nil {
		logger.LogError("GetTransactionReport: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate transaction report"})
	}

	return c.JSON(report)
}

// GetPaymentMethodDistribution returns the distribution of payment methods used in a time period
func (h *PaymentHandler) GetPaymentMethodDistribution(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetPaymentMethodDistribution: tenant_id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}

	// Parse date parameters with defaults
	startStr := c.Query("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endStr := c.Query("end_date", time.Now().Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		logger.LogError("GetPaymentMethodDistribution: invalid start_date", logger.ErrorField(err), logger.String("start_date", startStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid start_date format, use YYYY-MM-DD"})
	}

	endDate, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		logger.LogError("GetPaymentMethodDistribution: invalid end_date", logger.ErrorField(err), logger.String("end_date", endStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid end_date format, use YYYY-MM-DD"})
	}

	// Ensure end date is inclusive by extending to the end of the day
	endDate = endDate.Add(24*time.Hour - 1*time.Second)

	// Get the payment method distribution
	distribution, err := h.Store.GetPaymentMethodReport(c.Context(), tenantID, startDate, endDate)
	if err != nil {
		logger.LogError("GetPaymentMethodDistribution: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate payment method distribution"})
	}

	return c.JSON(fiber.Map{
		"start_date":                  startDate.Format("2006-01-02"),
		"end_date":                    endDate.Format("2006-01-02"),
		"payment_method_distribution": distribution,
	})
}

// GetTransactionVolume returns the total transaction volume and count for a time period
func (h *PaymentHandler) GetTransactionVolume(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("GetTransactionVolume: tenant_id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "tenant_id is required"})
	}

	// Parse date parameters with defaults
	startStr := c.Query("start_date", time.Now().AddDate(0, -1, 0).Format("2006-01-02"))
	endStr := c.Query("end_date", time.Now().Format("2006-01-02"))

	startDate, err := time.Parse("2006-01-02", startStr)
	if err != nil {
		logger.LogError("GetTransactionVolume: invalid start_date", logger.ErrorField(err), logger.String("start_date", startStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid start_date format, use YYYY-MM-DD"})
	}

	endDate, err := time.Parse("2006-01-02", endStr)
	if err != nil {
		logger.LogError("GetTransactionVolume: invalid end_date", logger.ErrorField(err), logger.String("end_date", endStr))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid end_date format, use YYYY-MM-DD"})
	}

	// Ensure end date is inclusive by extending to the end of the day
	endDate = endDate.Add(24*time.Hour - 1*time.Second)

	// Get the transaction volume and count
	volume, count, err := h.Store.GetTransactionVolume(c.Context(), tenantID, startDate, endDate)
	if err != nil {
		logger.LogError("GetTransactionVolume: failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to calculate transaction volume"})
	}

	return c.JSON(fiber.Map{
		"start_date":         startDate.Format("2006-01-02"),
		"end_date":           endDate.Format("2006-01-02"),
		"transaction_volume": volume,
		"transaction_count":  count,
	})
}

// GetPaymentPlugin returns details about a specific payment plugin
func (h *PaymentHandler) GetPaymentPlugin(c *fiber.Ctx) error {
	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("GetPaymentPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	plugin, exists := PaymentPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("GetPaymentPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Payment plugin '%s' not found", pluginName),
		})
	}

	return c.JSON(fiber.Map{
		"name":         plugin.Name(),
		"version":      plugin.Version(),
		"capabilities": plugin.Capabilities(),
	})
}

// ConfigurePaymentPlugin configures a payment plugin for a tenant
func (h *PaymentHandler) ConfigurePaymentPlugin(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("ConfigurePaymentPlugin: tenant_id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Tenant ID is required",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("ConfigurePaymentPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	// Check if the plugin exists
	plugin, exists := PaymentPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("ConfigurePaymentPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Payment plugin '%s' not found", pluginName),
		})
	}

	// Parse the configuration
	var config map[string]interface{}
	if err := c.BodyParser(&config); err != nil {
		logger.LogError("ConfigurePaymentPlugin: invalid configuration format", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid configuration format",
		})
	}

	// Initialize the plugin with the configuration
	if err := plugin.Initialize(config); err != nil {
		logger.LogError("ConfigurePaymentPlugin: failed to initialize plugin", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to initialize plugin: %v", err),
		})
	}

	// Save the configuration to the database
	pluginConfig := PaymentPluginConfig{
		TenantID:   tenantID,
		PluginName: pluginName,
		Config:     config,
		Enabled:    true,
		Default:    c.QueryBool("default", false),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save the configuration to the database
	// This is typically done by the store
	if h.Store != nil {
		ctx := c.Context()
		if err := h.Store.SavePaymentPluginConfig(ctx, &pluginConfig); err != nil {
			logger.LogError("ConfigurePaymentPlugin: failed to save plugin configuration", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to save plugin configuration: %v", err),
			})
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Payment plugin '%s' configured successfully for tenant '%s'", pluginName, tenantID),
	})
}

// DisablePaymentPlugin disables a payment plugin for a tenant
func (h *PaymentHandler) DisablePaymentPlugin(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		logger.LogError("DisablePaymentPlugin: tenant_id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Tenant ID is required",
		})
	}

	pluginName := c.Params("name")
	if pluginName == "" {
		logger.LogError("DisablePaymentPlugin: plugin name is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Plugin name is required",
		})
	}

	// Check if the plugin exists
	_, exists := PaymentPlugins.Lookup(pluginName)
	if !exists {
		logger.LogError("DisablePaymentPlugin: plugin not found", logger.String("plugin_name", pluginName))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Payment plugin '%s' not found", pluginName),
		})
	}

	// Disable the plugin in the database
	if h.Store != nil {
		ctx := c.Context()
		if err := h.Store.DisablePaymentPlugin(ctx, tenantID, pluginName); err != nil {
			logger.LogError("DisablePaymentPlugin: failed to disable plugin", logger.ErrorField(err))
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("Failed to disable plugin: %v", err),
			})
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Payment plugin '%s' disabled successfully for tenant '%s'", pluginName, tenantID),
	})
}

func (h *PaymentHandler) CreateManualRefund(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		logger.LogError("CreateManualRefund: id is required", logger.String("path", c.Path()))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	var input struct {
		Reason   string  `json:"reason"`
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
	}
	if err := c.BodyParser(&input); err != nil {
		logger.LogError("CreateManualRefund: invalid input", logger.ErrorField(err))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid input"})
	}
	refund := Refund{
		PaymentID: id,
		Reason:    input.Reason,
		Amount:    input.Amount,
		Currency:  input.Currency,
		Status:    "manual",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Metadata:  "{}",
	}
	refund, err := h.ManualRefundService.CreateManualRefund(c.Context(), refund)
	if err != nil {
		logger.LogError("CreateManualRefund: failed to create manual refund", logger.ErrorField(err))
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create manual refund"})
	}
	return c.Status(fiber.StatusCreated).JSON(refund)
}
