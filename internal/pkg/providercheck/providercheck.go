package providercheck

import (
	"context"
	"errors"

	"github.com/braintree-go/braintree-go"
	paypal "github.com/plutov/paypal/v4"
	"github.com/stripe/stripe-go/v75"
	stripeAccount "github.com/stripe/stripe-go/v75/account"
)

// PaymentProviderConfig is a minimal copy for connection check
// (should match internal/admin/server-config/types.go)
type PaymentProviderConfig struct {
	StripeAPIKey        string
	PaypalClientID      string
	PaypalClientSecret  string
	GooglePayMerchantID string
	GooglePayAPIKey     string
	ApplePayMerchantID  string
	ApplePayAPIKey      string
	PaymentsDisabled    bool
	BraintreeMerchantID string
	BraintreePublicKey  string
	BraintreePrivateKey string
	BraintreeEnv        string
}

func CheckPaymentProviderConnection(ctx context.Context, provider string, cfg *PaymentProviderConfig) error {
	switch provider {
	case "stripe":
		if cfg.StripeAPIKey == "" {
			return errors.New("stripe api_key missing")
		}
		stripe.Key = cfg.StripeAPIKey
		_, err := stripeAccount.Get()
		if err != nil {
			return errors.New("stripe connection failed: " + err.Error())
		}
		return nil
	case "paypal":
		if cfg.PaypalClientID == "" || cfg.PaypalClientSecret == "" {
			return errors.New("paypal client_id or client_secret missing")
		}
		client, err := paypal.NewClient(cfg.PaypalClientID, cfg.PaypalClientSecret, paypal.APIBaseSandBox)
		if err != nil {
			return errors.New("paypal client init failed: " + err.Error())
		}
		_, err = client.GetAccessToken(ctx)
		if err != nil {
			return errors.New("paypal connection failed: " + err.Error())
		}
		return nil
	case "braintree":
		if cfg.BraintreeMerchantID == "" || cfg.BraintreePublicKey == "" || cfg.BraintreePrivateKey == "" || cfg.BraintreeEnv == "" {
			return errors.New("braintree merchant_id, public_key, private_key, or env missing")
		}
		var btEnv braintree.Environment
		switch cfg.BraintreeEnv {
		case "sandbox":
			btEnv = braintree.Sandbox
		case "production":
			btEnv = braintree.Production
		default:
			return errors.New("invalid braintree env")
		}
		client := braintree.New(btEnv, cfg.BraintreeMerchantID, cfg.BraintreePublicKey, cfg.BraintreePrivateKey)
		_, err := client.Transaction().Search(ctx, &braintree.SearchQuery{})
		if err != nil {
			return errors.New("braintree connection failed: " + err.Error())
		}
		return nil
	default:
		return errors.New("unsupported provider: " + provider)
	}
}
