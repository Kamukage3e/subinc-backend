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

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// DisputeStoreInterface abstracts dispute storage for testability and multi-tenant support
// All methods must be robust, multi-tenant, and audit-friendly
type DisputeStoreInterface interface {
	CreateDispute(ctx context.Context, d *Dispute) error
	GetDispute(ctx context.Context, disputeID string) (*Dispute, error)
	ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error)
	UpdateDisputeStatus(ctx context.Context, disputeID string, status DisputeStatus, evidenceSubmitted *time.Time) error
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
		if p.AuditLogger != nil {
			go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "paypal_create_payment_unsupported_card",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if req.Source == PaymentMethodApplePay {
		err := errors.New("Direct Apple Pay not supported by PayPal Go SDK, use PayPal JS SDK on client")
		logger.LogError("paypal.create_payment.unsupported_apple_pay", logger.ErrorField(err), logger.String("source", req.Source))
		if p.AuditLogger != nil {
			go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "paypal_create_payment_unsupported_apple_pay",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if req.Source == PaymentMethodGooglePay {
		err := errors.New("Direct Google Pay not supported by PayPal Go SDK, use PayPal JS SDK on client")
		logger.LogError("paypal.create_payment.unsupported_google_pay", logger.ErrorField(err), logger.String("source", req.Source))
		if p.AuditLogger != nil {
			go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "paypal_create_payment_unsupported_google_pay",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if req.Source != "paypal" {
		err := errors.New("Unknown or unsupported payment source for PayPal")
		logger.LogError("paypal.create_payment.unsupported_source", logger.ErrorField(err), logger.String("source", req.Source))
		if p.AuditLogger != nil {
			go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "paypal_create_payment_unsupported_source",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
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
	if p.AuditLogger != nil {
		go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "paypal_create_payment",
			TargetID:  cap.ID,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": amount, "currency": cap.Amount.Currency, "status": cap.Status, "raw": cap}),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	if p.AuditLogger != nil {
		go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "paypal_refund_payment",
			TargetID:  req.PaymentID,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": amount, "currency": refund.Amount.Currency, "status": refund.Status, "raw": refund}),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	result, err := p.Store.GetPayment(ctx, paymentID)
	if err != nil {
		logger.LogError("paypal.get_payment_status.get_payment_failed", logger.ErrorField(err))
		if p.AuditLogger != nil {
			go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "paypal_get_payment_status_failed",
				TargetID:  paymentID,
				Details:   MarshalAuditDetails(map[string]interface{}{"error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if p.AuditLogger != nil {
		go p.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "paypal_get_payment_status",
			TargetID:  paymentID,
			Details:   MarshalAuditDetails(result),
			CreatedAt: time.Now().UTC(),
		})
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
		if s.AuditLogger != nil {
			go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "stripe_create_payment_unsupported_method",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
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
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "stripe_create_payment",
			TargetID:  intent.ID,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": float64(intent.Amount) / 100.0, "currency": string(intent.Currency), "status": intent.Status, "raw": intent}),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "stripe_refund_payment",
			TargetID:  req.PaymentID,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": float64(refund.Amount) / 100.0, "currency": string(refund.Currency), "status": refund.Status, "raw": refund}),
			CreatedAt: time.Now().UTC(),
		})
	}
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
	result, err := s.Store.GetPayment(ctx, paymentID)
	if err != nil {
		logger.LogError("stripe.get_payment_status.get_payment_failed", logger.ErrorField(err))
		if s.AuditLogger != nil {
			go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "stripe_get_payment_status_failed",
				TargetID:  paymentID,
				Details:   MarshalAuditDetails(map[string]interface{}{"error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "stripe_get_payment_status",
			TargetID:  paymentID,
			Details:   MarshalAuditDetails(result),
			CreatedAt: time.Now().UTC(),
		})
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
		if err != nil {
			logger.LogError("GetProviderForTenant: braintree client test failed", logger.ErrorField(err))
			return nil, err
		}
		return &BraintreeProvider{Client: client, AuditLogger: auditLogger, Store: store}, nil
	default:
		logger.LogError("GetProviderForTenant: unsupported provider", logger.String("provider", cfg.Provider))
		return nil, errors.New("unsupported provider: "+cfg.Provider)
	}
}

func getActorIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return "system"
	}
	if v := ctx.Value("user_id"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "system"
}

// NewStripeProvider returns a StripeProvider using merged owner/tenant config
func NewStripeProvider(ctx context.Context, store StoreInterface, tenantID string, auditLogger security_management.AuditLogger, configService *server_config.Service) (*StripeProvider, error) {
	ownerCfg, err := configService.GetOwnerPaymentProviderConfig(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := store.GetTenantProviderSecret(ctx, tenantID, "stripe")
	if err != nil {
		return nil, err
	}
	apiKey := ownerCfg.StripeAPIKey
	if v, ok := secret["api_key"]; ok && v != "" {
		apiKey = v
	}
	if apiKey == "" {
		return nil, errors.New("stripe api_key missing for tenant and owner")
	}
	return &StripeProvider{APIKey: apiKey, AuditLogger: auditLogger, Store: store}, nil
}

// NewPaypalProvider returns a PaypalProvider using merged owner/tenant config
func NewPaypalProvider(ctx context.Context, store StoreInterface, tenantID string, auditLogger security_management.AuditLogger, configService *server_config.Service) (*PaypalProvider, error) {
	ownerCfg, err := configService.GetOwnerPaymentProviderConfig(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := store.GetTenantProviderSecret(ctx, tenantID, "paypal")
	if err != nil {
		return nil, err
	}
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
		return nil, errors.New("paypal client_id, client_secret, or env missing for tenant and owner")
	}
	var apiBase string
	switch env {
	case "sandbox":
		apiBase = paypal.APIBaseSandBox
	case "live":
		apiBase = paypal.APIBaseLive
	default:
		return nil, errors.New("invalid paypal env")
	}
	client, err := paypal.NewClient(clientID, clientSecret, apiBase)
	if err != nil {
		return nil, err
	}
	return &PaypalProvider{Client: client, AuditLogger: auditLogger, Store: store}, nil
}

// NewBraintreeProvider returns a BraintreeProvider using merged owner/tenant config
func NewBraintreeProvider(ctx context.Context, store StoreInterface, tenantID string, auditLogger security_management.AuditLogger, configService *server_config.Service) (*BraintreeProvider, error) {
	ownerCfg, err := configService.GetOwnerPaymentProviderConfig(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := store.GetTenantProviderSecret(ctx, tenantID, "braintree")
	if err != nil {
		return nil, err
	}
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
		return nil, errors.New("braintree merchant_id, public_key, private_key, or env missing for tenant and owner")
	}
	var btEnv braintree.Environment
	switch env {
	case "sandbox":
		btEnv = braintree.Sandbox
	case "production":
		btEnv = braintree.Production
	default:
		return nil, errors.New("invalid braintree env")
	}
	client := braintree.New(btEnv, merchantID, publicKey, privateKey)
	_, err = client.Transaction().Search(ctx, &braintree.SearchQuery{})
	return &BraintreeProvider{Client: client, AuditLogger: auditLogger, Store: store}, err
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
	var paymentMethod string
	switch req.Source {
	case PaymentMethodCard:
		paymentMethod = req.Metadata["nonce"]
	case PaymentMethodGooglePay:
		paymentMethod = req.Metadata["nonce"]
	case PaymentMethodApplePay:
		paymentMethod = req.Metadata["nonce"]
	default:
		err := errors.New("unsupported payment method for Braintree")
		logger.LogError("braintree.create_payment.unsupported_method", logger.ErrorField(err), logger.String("source", req.Source))
		if b.AuditLogger != nil {
			go b.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "braintree_create_payment_unsupported_method",
				TargetID:  "",
				Details:   MarshalAuditDetails(map[string]interface{}{"source": req.Source, "error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if paymentMethod == "" {
		err := errors.New("payment method nonce required")
		logger.LogError("braintree.create_payment.missing_nonce", logger.ErrorField(err))
		return nil, err
	}
	btReq := &braintree.TransactionRequest{
		Type:               "sale",
		Amount:             braintree.NewDecimal(int64(req.Amount*100), 2),
		PaymentMethodNonce: paymentMethod,
		Options: &braintree.TransactionOptions{
			SubmitForSettlement: true,
		},
		OrderId: req.Metadata["order_id"],
	}
	btTx, err := b.Client.Transaction().Create(ctx, btReq)
	if err != nil {
		logger.LogError("braintree.create_payment.failed", logger.ErrorField(err))
		return nil, errors.New("braintree: failed to create transaction")
	}
	result := &PaymentResult{
		PaymentID: btTx.Id,
		Status:    string(btTx.Status),
		Amount:    req.Amount,
		Currency:  req.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "braintree",
		Raw:       btTx,
	}
	if err := b.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("braintree.create_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	if b.AuditLogger != nil {
		go b.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "braintree_create_payment",
			TargetID:  btTx.Id,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": req.Amount, "currency": req.Currency, "status": btTx.Status, "raw": btTx}),
			CreatedAt: time.Now().UTC(),
		})
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
	if req.PaymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("braintree.refund_payment.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	btTx, err := b.Client.Transaction().Refund(ctx, req.PaymentID)
	if err != nil {
		logger.LogError("braintree.refund_payment.failed", logger.ErrorField(err))
		return nil, errors.New("braintree: failed to refund transaction")
	}
	result := &PaymentResult{
		PaymentID: req.PaymentID,
		Status:    string(btTx.Status),
		Amount:    req.Amount,
		Currency:  req.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  "braintree",
		Raw:       btTx,
	}
	if err := b.Store.SavePayment(ctx, result); err != nil {
		logger.LogError("braintree.refund_payment.save_payment_failed", logger.ErrorField(err))
		return nil, err
	}
	if b.AuditLogger != nil {
		go b.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "braintree_refund_payment",
			TargetID:  req.PaymentID,
			Details:   MarshalAuditDetails(map[string]interface{}{"amount": req.Amount, "currency": req.Currency, "status": btTx.Status, "raw": btTx}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return result, nil
}

func (b *BraintreeProvider) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	if paymentID == "" {
		err := errors.New("payment_id must not be empty")
		logger.LogError("braintree.get_payment_status.missing_payment_id", logger.ErrorField(err))
		return nil, err
	}
	result, err := b.Store.GetPayment(ctx, paymentID)
	if err != nil {
		logger.LogError("braintree.get_payment_status.get_payment_failed", logger.ErrorField(err))
		if b.AuditLogger != nil {
			go b.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "braintree_get_payment_status_failed",
				TargetID:  paymentID,
				Details:   MarshalAuditDetails(map[string]interface{}{"error": err.Error()}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return nil, err
	}
	if b.AuditLogger != nil {
		go b.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "braintree_get_payment_status",
			TargetID:  paymentID,
			Details:   MarshalAuditDetails(result),
			CreatedAt: time.Now().UTC(),
		})
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

func CheckProviderConnection(ctx context.Context, store StoreInterface, tenantID, providerName string, configService *server_config.Service) error {
	err := error(nil)
	action := "check_provider_connection"
	details := map[string]interface{}{"tenant_id": tenantID, "provider": providerName}
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
		env := ownerCfg.PaypalClientSecret
		if v, ok := secret["env"]; ok && v != "" {
			env = v
		}
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
	// Audit log
	auditLogger, _ := ctx.Value("audit_logger").(security_management.AuditLogger)
	if auditLogger != nil {
		go auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    action,
			TargetID:  providerName,
			Details:   MarshalAuditDetails(details),
			CreatedAt: time.Now().UTC(),
		})
	}
	return err
}

func RetryPayment(ctx context.Context, store StoreInterface, p interface{}) (*PaymentResult, error) {
	failed, ok := p.(*FailedPayment)
	if !ok || failed == nil {
		logger.LogError("RetryPayment: invalid payment type", logger.ErrorField(errors.New("invalid payment type")))
		return nil, errors.New("invalid payment type")
	}
	pay, err := store.GetPayment(ctx, failed.ID)
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
		auditLogger, _ := ctx.Value("audit_logger").(security_management.AuditLogger)
		if auditLogger != nil {
			go auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
				ActorID:   getActorIDFromContext(ctx),
				Action:    "retry_payment_failed",
				TargetID:  pay.PaymentID,
				Details:   MarshalAuditDetails(map[string]interface{}{"error": err.Error(), "payment_id": pay.PaymentID}),
				CreatedAt: time.Now().UTC(),
			})
		}
		return &PaymentResult{PaymentID: pay.PaymentID, Status: "failed", Amount: pay.Amount, Currency: pay.Currency, CreatedAt: time.Now().UTC(), Provider: pay.Provider}, err
	}
	// Audit log success
	auditLogger, _ := ctx.Value("audit_logger").(security_management.AuditLogger)
	if auditLogger != nil {
		go auditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "retry_payment_success",
			TargetID:  result.PaymentID,
			Details:   MarshalAuditDetails(result),
			CreatedAt: time.Now().UTC(),
		})
	}
	return result, nil
}

// DisputeService handles dispute/chargeback logic for all providers
// All methods are robust, multi-tenant, audit-logged, and notify on state change

// IngestDisputeEvent ingests a dispute/chargeback event from a provider webhook
func (s *DisputeService) IngestDisputeEvent(ctx context.Context, d *Dispute) error {
	if d == nil {
		return errors.New("dispute must not be nil")
	}
	d.CreatedAt = time.Now().UTC()
	d.UpdatedAt = d.CreatedAt
	err := s.Store.CreateDispute(ctx, d)
	if err != nil {
		logger.LogError("IngestDisputeEvent: create failed", logger.ErrorField(err))
		return err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_ingest",
			TargetID:  d.ID,
			Details:   MarshalAuditDetails(d),
			CreatedAt: d.CreatedAt,
		})
	}
	if s.Notify != nil {
		_ = s.Notify.SendNotification(ctx, d.TenantID, "dispute_opened", map[string]interface{}{"dispute_id": d.ID, "payment_id": d.PaymentID, "status": d.Status, "reason": d.Reason})
	}
	return nil
}

// ListDisputes returns disputes for a tenant/payment
func (s *DisputeService) ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error) {
	disputes, err := s.Store.ListDisputes(ctx, tenantID, paymentID, status, page, pageSize)
	if err != nil {
		logger.LogError("ListDisputes: failed", logger.ErrorField(err))
		return nil, err
	}
	return disputes, nil
}

// GetDispute fetches a dispute by ID
func (s *DisputeService) GetDispute(ctx context.Context, disputeID string) (*Dispute, error) {
	dispute, err := s.Store.GetDispute(ctx, disputeID)
	if err != nil {
		logger.LogError("GetDispute: failed", logger.ErrorField(err))
		return nil, err
	}
	return dispute, nil
}

// UpdateDisputeStatus updates dispute status and notifies/audits
func (s *DisputeService) UpdateDisputeStatus(ctx context.Context, disputeID string, status DisputeStatus, evidenceSubmitted *time.Time) error {
	err := s.Store.UpdateDisputeStatus(ctx, disputeID, status, evidenceSubmitted)
	if err != nil {
		logger.LogError("UpdateDisputeStatus: failed", logger.ErrorField(err))
		return err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_status_update",
			TargetID:  disputeID,
			Details:   MarshalAuditDetails(map[string]interface{}{"status": status, "evidence_submitted": evidenceSubmitted}),
			CreatedAt: time.Now().UTC(),
		})
	}
	if s.Notify != nil {
		_ = s.Notify.SendNotification(ctx, "", "dispute_status_changed", map[string]interface{}{"dispute_id": disputeID, "status": status})
	}
	return nil
}

// UploadEvidence handles file upload, DB insert, audit, and notification
func (s *DisputeEvidenceService) UploadEvidence(ctx context.Context, e *DisputeEvidence) error {
	if e == nil {
		return errors.New("evidence must not be nil")
	}
	e.CreatedAt = time.Now().UTC()
	e.UpdatedAt = e.CreatedAt
	err := s.Store.CreateDisputeEvidence(ctx, e)
	if err != nil {
		logger.LogError("UploadEvidence: create failed", logger.ErrorField(err))
		return err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_evidence_upload",
			TargetID:  e.ID,
			Details:   MarshalAuditDetails(e),
			CreatedAt: e.CreatedAt,
		})
	}
	if s.Notify != nil {
		_ = s.Notify.SendNotification(ctx, e.TenantID, "dispute_evidence_uploaded", map[string]interface{}{"evidence_id": e.ID, "dispute_id": e.DisputeID, "file_name": e.FileName})
	}
	return nil
}

// ListEvidence returns evidence for a dispute/tenant
func (s *DisputeEvidenceService) ListEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error) {
	list, err := s.Store.ListDisputeEvidence(ctx, disputeID, tenantID, page, pageSize)
	if err != nil {
		logger.LogError("ListEvidence: failed", logger.ErrorField(err))
		return nil, err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_evidence_list",
			TargetID:  disputeID,
			Details:   MarshalAuditDetails(map[string]interface{}{"page": page, "page_size": pageSize}),
			CreatedAt: time.Now().UTC(),
		})
	}
	return list, nil
}

// GetEvidence fetches an evidence record by ID
func (s *DisputeEvidenceService) GetEvidence(ctx context.Context, evidenceID string) (*DisputeEvidence, error) {
	e, err := s.Store.GetDisputeEvidence(ctx, evidenceID)
	if err != nil {
		logger.LogError("GetEvidence: failed", logger.ErrorField(err))
		return nil, err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_evidence_get",
			TargetID:  evidenceID,
			Details:   MarshalAuditDetails(e),
			CreatedAt: e.CreatedAt,
		})
	}
	return e, nil
}

// UpdateEvidenceStatus updates provider status/response, audits, and notifies
func (s *DisputeEvidenceService) UpdateEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error {
	err := s.Store.UpdateDisputeEvidenceStatus(ctx, evidenceID, providerStatus, providerResponse)
	if err != nil {
		logger.LogError("UpdateEvidenceStatus: failed", logger.ErrorField(err))
		return err
	}
	if s.AuditLogger != nil {
		go s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
			ActorID:   getActorIDFromContext(ctx),
			Action:    "dispute_evidence_status_update",
			TargetID:  evidenceID,
			Details:   MarshalAuditDetails(map[string]interface{}{"provider_status": providerStatus, "provider_response": providerResponse}),
			CreatedAt: time.Now().UTC(),
		})
	}
	if s.Notify != nil {
		_ = s.Notify.SendNotification(ctx, "", "dispute_evidence_status_changed", map[string]interface{}{"evidence_id": evidenceID, "provider_status": providerStatus})
	}
	return nil
}
