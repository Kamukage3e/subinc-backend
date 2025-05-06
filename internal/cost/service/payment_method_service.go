package service

import (
	"context"

	"time"

	"github.com/spf13/viper"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/paymentmethod"
	"github.com/subinc/subinc-backend/internal/cost/domain"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type PaymentMethodService interface {
	AddPaymentMethod(ctx context.Context, method *domain.PaymentMethod, paymentData map[string]string) error
	UpdatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error
	RemovePaymentMethod(ctx context.Context, id string) error
	SetDefaultPaymentMethod(ctx context.Context, accountID, id string) error
	GetPaymentMethodByID(ctx context.Context, id string) (*domain.PaymentMethod, error)
	ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.PaymentMethod, int, error)
}

type paymentMethodService struct {
	repo      repository.BillingRepository
	logger    *logger.Logger
	providers *TokenizationProviderRegistry
}

func NewPaymentMethodService(repo repository.BillingRepository, log *logger.Logger, providers *TokenizationProviderRegistry) PaymentMethodService {
	if log == nil {
		log = logger.NewNoop()
	}
	return &paymentMethodService{repo: repo, logger: log, providers: providers}
}

func (s *paymentMethodService) AddPaymentMethod(ctx context.Context, method *domain.PaymentMethod, paymentData map[string]string) error {
	if method == nil {
		s.logger.Error("nil payment method provided")
		return domain.NewValidationError("payment_method", "must not be nil")
	}
	if paymentData == nil {
		s.logger.Error("nil payment data provided")
		return domain.NewValidationError("payment_data", "must not be nil")
	}
	providerName := method.TokenProvider
	if providerName == "" {
		providerName = method.Provider // fallback to method.Provider if TokenProvider not set
	}
	provider, err := s.providers.GetProvider(providerName)
	if err != nil {
		s.logger.Error("tokenization provider selection failed", logger.String("provider", providerName), logger.ErrorField(err))
		return err
	}
	s.logger.Info("selected tokenization provider", logger.String("provider", providerName), logger.String("account_id", method.AccountID))
	token, err := provider.CreateToken(ctx, method.AccountID, paymentData)
	if err != nil {
		s.logger.Error("tokenization failed", logger.ErrorField(err), logger.String("account_id", method.AccountID), logger.String("provider", providerName))
		return err
	}
	method.Token = token
	method.TokenProvider = provider.ProviderName()
	method.ID = uuid.NewString()
	method.Status = "active"
	method.CreatedAt = time.Now().UTC()
	method.UpdatedAt = method.CreatedAt
	return s.repo.CreatePaymentMethod(ctx, method)
}

func (s *paymentMethodService) UpdatePaymentMethod(ctx context.Context, method *domain.PaymentMethod) error {
	if method == nil {
		s.logger.Error("nil payment method provided")
		return domain.NewValidationError("payment_method", "must not be nil")
	}
	method.UpdatedAt = time.Now().UTC()
	return s.repo.UpdatePaymentMethod(ctx, method)
}

func (s *paymentMethodService) RemovePaymentMethod(ctx context.Context, id string) error {
	if id == "" {
		s.logger.Error("empty payment method id for remove")
		return domain.NewValidationError("payment_method_id", "must not be empty")
	}
	return s.repo.DeletePaymentMethod(ctx, id)
}

func (s *paymentMethodService) SetDefaultPaymentMethod(ctx context.Context, accountID, id string) error {
	if accountID == "" || id == "" {
		s.logger.Error("empty account or payment method id for set default")
		return domain.NewValidationError("payment_method", "accountID and id required")
	}
	methods, _, err := s.repo.ListPaymentMethods(ctx, accountID, "active", 1, 100)
	if err != nil {
		s.logger.Error("failed to list payment methods for set default", logger.ErrorField(err))
		return err
	}
	for _, m := range methods {
		if m.IsDefault && m.ID != id {
			m.IsDefault = false
			m.UpdatedAt = time.Now().UTC()
			_ = s.repo.UpdatePaymentMethod(ctx, m)
		}
		if m.ID == id {
			m.IsDefault = true
			m.UpdatedAt = time.Now().UTC()
			if err := s.repo.UpdatePaymentMethod(ctx, m); err != nil {
				s.logger.Error("failed to set default payment method", logger.ErrorField(err))
				return err
			}
		}
	}
	return nil
}

func (s *paymentMethodService) GetPaymentMethodByID(ctx context.Context, id string) (*domain.PaymentMethod, error) {
	return s.repo.GetPaymentMethodByID(ctx, id)
}

func (s *paymentMethodService) ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]*domain.PaymentMethod, int, error) {
	return s.repo.ListPaymentMethods(ctx, accountID, status, page, pageSize)
}

// StripeTokenizationProvider implements TokenizationProvider using Stripe Elements API
// All sensitive card data is sent directly to Stripe from the client; backend only receives tokens
// This implementation is PCI-compliant and never stores or handles raw card data
type StripeTokenizationProvider struct {
	apiKey string
}

func NewStripeTokenizationProvider() *StripeTokenizationProvider {
	if viper.GetString("payments.disabled") == "true" {
		return &StripeTokenizationProvider{apiKey: "dummy-stripe-key"}
	}
	apiKey := viper.GetString("payments.stripe_api_key")
	if apiKey == "" {
		// In production, fail fast with clear error; in dev/test, return dummy provider
		if viper.GetString("env") == "production" {
			panic("STRIPE_API_KEY not set: required for production payments") // Explicitly panic in prod for safety
		}
		return &StripeTokenizationProvider{apiKey: "dummy-stripe-key"}
	}
	stripe.Key = apiKey
	return &StripeTokenizationProvider{apiKey: apiKey}
}

func (s *StripeTokenizationProvider) CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return "dummy-token", nil
	}
	// paymentData must contain a Stripe payment method token (from client)
	token, ok := paymentData["stripe_token"]
	if !ok || token == "" {
		return "", domain.NewValidationError("stripe_token", "must be provided by client (PCI compliance)")
	}
	// Optionally, attach to customer in Stripe here if needed
	return token, nil
}

func (s *StripeTokenizationProvider) GetToken(ctx context.Context, accountID, token string) (map[string]string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return map[string]string{"provider": "stripe", "token": token, "last4": "0000", "brand": "dummy"}, nil
	}
	pm, err := paymentmethod.Get(token, nil)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{
		"last4":     pm.Card.Last4,
		"exp_month": string(rune(pm.Card.ExpMonth)),
		"exp_year":  string(rune(pm.Card.ExpYear)),
		"brand":     string(pm.Card.Brand),
	}
	return meta, nil
}

func (s *StripeTokenizationProvider) DeleteToken(ctx context.Context, accountID, token string) error {
	if viper.GetString("payments.disabled") == "true" {
		return nil
	}
	_, err := paymentmethod.Detach(token, nil)
	return err
}

func (s *StripeTokenizationProvider) ProviderName() string {
	return "stripe"
}

// TokenizationProviderRegistry manages multiple tokenization providers for payment methods
// This enables runtime selection of provider based on method/provider type
// All implementations must be secure, production-grade, and never store sensitive data in the DB

type TokenizationProviderRegistry struct {
	providers map[string]domain.TokenizationProvider
	logger    *logger.Logger
}

func NewTokenizationProviderRegistry(logger *logger.Logger, providers ...domain.TokenizationProvider) *TokenizationProviderRegistry {
	reg := &TokenizationProviderRegistry{
		providers: make(map[string]domain.TokenizationProvider),
		logger:    logger,
	}
	for _, p := range providers {
		reg.providers[p.ProviderName()] = p
	}
	return reg
}

func (r *TokenizationProviderRegistry) GetProvider(name string) (domain.TokenizationProvider, error) {
	p, ok := r.providers[name]
	if !ok {
		r.logger.Error("tokenization provider not found", logger.String("provider", name))
		return nil, domain.NewValidationError("token_provider", "unsupported or missing tokenization provider")
	}
	return p, nil
}

// --- PayPalTokenizationProvider ---
type PayPalTokenizationProvider struct {
	clientID     string
	clientSecret string
	apiBase      string
	httpClient   *http.Client
}

func NewPayPalTokenizationProvider() *PayPalTokenizationProvider {
	if viper.GetString("payments.disabled") == "true" {
		return &PayPalTokenizationProvider{
			clientID:     "dummy-paypal-client-id",
			clientSecret: "dummy-paypal-client-secret",
			apiBase:      "https://api.sandbox.paypal.com",
			httpClient:   &http.Client{Timeout: 5 * time.Second},
		}
	}
	clientID := viper.GetString("payments.paypal_client_id")
	clientSecret := viper.GetString("payments.paypal_client_secret")
	apiBase := viper.GetString("payments.paypal_api_base")
	if apiBase == "" {
		apiBase = "https://api.paypal.com"
	}
	if clientID == "" || clientSecret == "" {
		if viper.GetString("env") == "production" {
			panic("PayPal credentials not set in env: required for production payments") // Explicitly panic in prod for safety
		}
		return &PayPalTokenizationProvider{
			clientID:     "dummy-paypal-client-id",
			clientSecret: "dummy-paypal-client-secret",
			apiBase:      "https://api.sandbox.paypal.com",
			httpClient:   &http.Client{Timeout: 5 * time.Second},
		}
	}
	return &PayPalTokenizationProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		apiBase:      apiBase,
		httpClient:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (p *PayPalTokenizationProvider) getAccessToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiBase+"/v1/oauth2/token", bytes.NewBufferString("grant_type=client_credentials"))
	if err != nil {
		return "", fmt.Errorf("paypal: failed to create token request: %w", err)
	}
	req.SetBasicAuth(p.clientID, p.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("paypal: token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("paypal: token request status %d: %s", resp.StatusCode, string(b))
	}
	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("paypal: failed to decode token response: %w", err)
	}
	return res.AccessToken, nil
}

func (p *PayPalTokenizationProvider) CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return "dummy-token", nil
	}
	token, ok := paymentData["paypal_token"]
	if !ok || token == "" {
		return "", domain.NewValidationError("paypal_token", "must be provided by client (PCI compliance)")
	}
	return token, nil
}

func (p *PayPalTokenizationProvider) GetToken(ctx context.Context, accountID, token string) (map[string]string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return map[string]string{"provider": "paypal", "token": token, "last4": "0000", "brand": "dummy"}, nil
	}
	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/vault/payment-tokens/%s", p.apiBase, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("paypal: failed to create get token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paypal: get token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("paypal: get token status %d: %s", resp.StatusCode, string(b))
	}
	var meta map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("paypal: failed to decode token metadata: %w", err)
	}
	result := map[string]string{"provider": "paypal", "token": token}
	if v, ok := meta["last_digits"].(string); ok {
		result["last4"] = v
	}
	if v, ok := meta["brand"].(string); ok {
		result["brand"] = v
	}
	return result, nil
}

func (p *PayPalTokenizationProvider) DeleteToken(ctx context.Context, accountID, token string) error {
	if viper.GetString("payments.disabled") == "true" {
		return nil
	}
	accessToken, err := p.getAccessToken(ctx)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v1/vault/payment-tokens/%s", p.apiBase, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("paypal: failed to create delete token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("paypal: delete token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("paypal: delete token status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (p *PayPalTokenizationProvider) ProviderName() string { return "paypal" }

// --- GooglePayTokenizationProvider ---
type GooglePayTokenizationProvider struct {
	merchantID string
	apiKey     string
	apiBase    string
	httpClient *http.Client
}

func NewGooglePayTokenizationProvider() *GooglePayTokenizationProvider {
	if viper.GetString("payments.disabled") == "true" {
		return &GooglePayTokenizationProvider{
			merchantID: "dummy-googlepay-merchant-id",
			apiKey:     "dummy-googlepay-api-key",
			apiBase:    "https://payments.googleapis.com",
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}
	}
	merchantID := viper.GetString("payments.googlepay_merchant_id")
	apiKey := viper.GetString("payments.googlepay_api_key")
	apiBase := viper.GetString("payments.googlepay_api_base")
	if apiBase == "" {
		apiBase = "https://payments.googleapis.com"
	}
	if merchantID == "" || apiKey == "" {
		if viper.GetString("env") == "production" {
			panic("Google Pay credentials not set in env: required for production payments")
		}
		return &GooglePayTokenizationProvider{
			merchantID: "dummy-googlepay-merchant-id",
			apiKey:     "dummy-googlepay-api-key",
			apiBase:    "https://payments.googleapis.com",
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}
	}
	return &GooglePayTokenizationProvider{
		merchantID: merchantID,
		apiKey:     apiKey,
		apiBase:    apiBase,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (g *GooglePayTokenizationProvider) CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return "dummy-token", nil
	}
	token, ok := paymentData["googlepay_token"]
	if !ok || token == "" {
		return "", domain.NewValidationError("googlepay_token", "must be provided by client (PCI compliance)")
	}
	return token, nil
}

func (g *GooglePayTokenizationProvider) GetToken(ctx context.Context, accountID, token string) (map[string]string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return map[string]string{"provider": "googlepay", "token": token, "last4": "0000", "brand": "dummy"}, nil
	}
	url := fmt.Sprintf("%s/v1/paymentTokens/%s?merchantId=%s", g.apiBase, token, g.merchantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("googlepay: failed to create get token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("googlepay: get token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("googlepay: get token status %d: %s", resp.StatusCode, string(b))
	}
	var meta map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("googlepay: failed to decode token metadata: %w", err)
	}
	result := map[string]string{"provider": "googlepay", "token": token}
	if v, ok := meta["last4"].(string); ok {
		result["last4"] = v
	}
	if v, ok := meta["brand"].(string); ok {
		result["brand"] = v
	}
	return result, nil
}

func (g *GooglePayTokenizationProvider) DeleteToken(ctx context.Context, accountID, token string) error {
	if viper.GetString("payments.disabled") == "true" {
		return nil
	}
	url := fmt.Sprintf("%s/v1/paymentTokens/%s?merchantId=%s", g.apiBase, token, g.merchantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("googlepay: failed to create delete token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("googlepay: delete token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("googlepay: delete token status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (g *GooglePayTokenizationProvider) ProviderName() string { return "googlepay" }

// --- ApplePayTokenizationProvider ---
type ApplePayTokenizationProvider struct {
	merchantID string
	apiKey     string
	apiBase    string
	httpClient *http.Client
}

func NewApplePayTokenizationProvider() *ApplePayTokenizationProvider {
	if viper.GetString("payments.disabled") == "true" {
		return &ApplePayTokenizationProvider{
			merchantID: "dummy-applepay-merchant-id",
			apiKey:     "dummy-applepay-api-key",
			apiBase:    "https://apple-pay-gateway.apple.com",
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}
	}
	merchantID := viper.GetString("payments.applepay_merchant_id")
	apiKey := viper.GetString("payments.applepay_api_key")
	apiBase := viper.GetString("payments.applepay_api_base")
	if apiBase == "" {
		apiBase = "https://apple-pay-gateway.apple.com"
	}
	if merchantID == "" || apiKey == "" {
		if viper.GetString("env") == "production" {
			panic("Apple Pay credentials not set in env: required for production payments")
		}
		return &ApplePayTokenizationProvider{
			merchantID: "dummy-applepay-merchant-id",
			apiKey:     "dummy-applepay-api-key",
			apiBase:    "https://apple-pay-gateway.apple.com",
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}
	}
	return &ApplePayTokenizationProvider{
		merchantID: merchantID,
		apiKey:     apiKey,
		apiBase:    apiBase,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *ApplePayTokenizationProvider) CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return "dummy-token", nil
	}
	token, ok := paymentData["applepay_token"]
	if !ok || token == "" {
		return "", domain.NewValidationError("applepay_token", "must be provided by client (PCI compliance)")
	}
	return token, nil
}

func (a *ApplePayTokenizationProvider) GetToken(ctx context.Context, accountID, token string) (map[string]string, error) {
	if viper.GetString("payments.disabled") == "true" {
		return map[string]string{"provider": "applepay", "token": token, "last4": "0000", "brand": "dummy"}, nil
	}
	url := fmt.Sprintf("%s/paymentservices/paymentTokens/%s?merchantIdentifier=%s", a.apiBase, token, a.merchantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("applepay: failed to create get token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("applepay: get token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("applepay: get token status %d: %s", resp.StatusCode, string(b))
	}
	var meta map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("applepay: failed to decode token metadata: %w", err)
	}
	result := map[string]string{"provider": "applepay", "token": token}
	if v, ok := meta["last4"].(string); ok {
		result["last4"] = v
	}
	if v, ok := meta["brand"].(string); ok {
		result["brand"] = v
	}
	return result, nil
}

func (a *ApplePayTokenizationProvider) DeleteToken(ctx context.Context, accountID, token string) error {
	if viper.GetString("payments.disabled") == "true" {
		return nil
	}
	url := fmt.Sprintf("%s/paymentservices/paymentTokens/%s?merchantIdentifier=%s", a.apiBase, token, a.merchantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("applepay: failed to create delete token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("applepay: delete token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("applepay: delete token status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (a *ApplePayTokenizationProvider) ProviderName() string { return "applepay" }

// DummyTokenizationProvider implements TokenizationProvider for disabled payments
// Returns static tokens and does not require any credentials
// Used when PAYMENTS_DISABLED=true for local/dev/test
// All methods are no-ops and never panic

type DummyTokenizationProvider struct{}

func (d *DummyTokenizationProvider) CreateToken(ctx context.Context, accountID string, paymentData map[string]string) (string, error) {
	return "dummy-token", nil
}

func (d *DummyTokenizationProvider) GetToken(ctx context.Context, accountID, token string) (map[string]string, error) {
	return map[string]string{"provider": "dummy", "token": token, "last4": "0000", "brand": "dummy"}, nil
}

func (d *DummyTokenizationProvider) DeleteToken(ctx context.Context, accountID, token string) error {
	return nil
}

func (d *DummyTokenizationProvider) ProviderName() string { return "dummy" }

// NewDefaultTokenizationProviderRegistry wires up all prod providers using env/config
// If PAYMENTS_DISABLED=true, only dummy provider is registered
func NewDefaultTokenizationProviderRegistry(logger *logger.Logger) *TokenizationProviderRegistry {
	if viper.GetString("payments.disabled") == "true" {
		logger.Warn("Payments are DISABLED via PAYMENTS_DISABLED env; using dummy tokenization provider only")
		return NewTokenizationProviderRegistry(logger, &DummyTokenizationProvider{})
	}
	return NewTokenizationProviderRegistry(
		logger,
		NewStripeTokenizationProvider(),
		NewPayPalTokenizationProvider(),
		NewGooglePayTokenizationProvider(),
		NewApplePayTokenizationProvider(),
	)
}
