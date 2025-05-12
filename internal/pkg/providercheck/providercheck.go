package providercheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/braintree-go/braintree-go"
	"github.com/golang-jwt/jwt/v5"
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

// OAuthConfig contains configuration for OAuth provider checks
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Provider     string
}

// SAMLConfig contains configuration for SAML metadata checks
type SAMLConfig struct {
	MetadataURL string
}

// JWTConfig contains configuration for JWT validation
type JWTConfig struct {
	Secret string
}

// OpenAIConfig contains configuration for OpenAI API validation
type OpenAIConfig struct {
	APIKey string
	APIURL string
}

// WebhookConfig contains configuration for webhook endpoint validation
type WebhookConfig struct {
	EndpointURL string
}

// SMTPConfig contains configuration for SMTP server validation
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	UseSSL   bool
	UseTLS   bool
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

// CheckJWTSecret validates a JWT secret by creating and validating a test token
func CheckJWTSecret(ctx context.Context, cfg *JWTConfig) error {
	if cfg.Secret == "" {
		return errors.New("jwt secret missing")
	}

	// Create a test JWT token with the secret
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = "test-subject"
	claims["exp"] = time.Now().Add(time.Minute).Unix()
	claims["iat"] = time.Now().Unix()
	claims["nbf"] = time.Now().Unix()
	claims["iss"] = "test-issuer"
	claims["jti"] = fmt.Sprintf("test-%d", time.Now().Unix())

	tokenString, jwtErr := token.SignedString([]byte(cfg.Secret))
	if jwtErr != nil {
		return errors.New("failed to create token: " + jwtErr.Error())
	}

	// Validate token
	_, jwtErr = jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.Secret), nil
	})
	if jwtErr != nil {
		return errors.New("failed to validate token: " + jwtErr.Error())
	}

	return nil
}

// CheckOAuthCredentials validates OAuth provider credentials
func CheckOAuthCredentials(ctx context.Context, cfg *OAuthConfig) error {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return errors.New("client_id or client_secret missing")
	}

	switch cfg.Provider {
	case "google":
		// Create a test request to Google's OAuth2 token endpoint
		tokenURL := "https://oauth2.googleapis.com/token"
		requestData := fmt.Sprintf(
			"client_id=%s&client_secret=%s&grant_type=client_credentials",
			cfg.ClientID,
			cfg.ClientSecret,
		)

		req, _ := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(requestData))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("error connecting to Google OAuth API: " + err.Error())
		}
		defer resp.Body.Close()

		// If the credentials are invalid, Google will return a 4xx error
		if resp.StatusCode >= 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("invalid credentials. Status: %d, Response: %s", resp.StatusCode, string(bodyBytes))
		}
		return nil
	default:
		return errors.New("unsupported OAuth provider: " + cfg.Provider)
	}
}

// CheckSAMLMetadata validates a SAML metadata URL
func CheckSAMLMetadata(ctx context.Context, cfg *SAMLConfig) error {
	if cfg.MetadataURL == "" {
		return errors.New("metadata URL missing")
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.MetadataURL, nil)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("error connecting to SAML metadata URL: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to fetch SAML metadata. Status: %d, Response: %s", resp.StatusCode, string(bodyBytes))
	}

	// Try to parse the XML to ensure it's valid SAML metadata
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return errors.New("error reading SAML metadata: " + readErr.Error())
	}

	// Basic validation - ensure it contains key SAML elements
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, "EntityDescriptor") ||
		(!strings.Contains(bodyStr, "IDPSSODescriptor") && !strings.Contains(bodyStr, "SPSSODescriptor")) {
		return errors.New("URL does not contain valid SAML metadata")
	}

	return nil
}

// CheckOpenAIAPIKey validates an OpenAI API key
func CheckOpenAIAPIKey(ctx context.Context, cfg *OpenAIConfig) error {
	if cfg.APIKey == "" {
		return errors.New("API key missing")
	}

	// Default to the official OpenAI API URL if not specified
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = "https://api.openai.com"
	}

	// Use models endpoint to verify API key (lightweight request)
	modelsURL := apiURL + "/v1/models"
	req, _ := http.NewRequestWithContext(ctx, "GET", modelsURL, nil)
	req.Header.Add("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("error connecting to OpenAI API: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("invalid API key. Status: %d, Response: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CheckWebhookEndpoint validates a webhook endpoint
func CheckWebhookEndpoint(ctx context.Context, cfg *WebhookConfig) error {
	if cfg.EndpointURL == "" {
		return errors.New("webhook endpoint URL missing")
	}

	// Try a HEAD request first to check connectivity without sending data
	req, _ := http.NewRequestWithContext(ctx, "HEAD", cfg.EndpointURL, nil)
	req.Header.Add("User-Agent", "SubInc-Backend-Config-Test")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("error connecting to webhook endpoint: " + err.Error())
	}
	resp.Body.Close()

	// Now try a small POST with test data to verify it accepts webhook payloads
	testPayload := map[string]interface{}{
		"event": "test_event",
		"data": map[string]interface{}{
			"test":      true,
			"timestamp": time.Now().Unix(),
		},
	}

	jsonPayload, _ := json.Marshal(testPayload)
	postReq, _ := http.NewRequestWithContext(ctx, "POST", cfg.EndpointURL, bytes.NewBuffer(jsonPayload))
	postReq.Header.Add("Content-Type", "application/json")
	postReq.Header.Add("User-Agent", "SubInc-Backend-Config-Test")

	postResp, postErr := client.Do(postReq)
	if postErr != nil {
		return errors.New("error posting to webhook endpoint: " + postErr.Error())
	}
	defer postResp.Body.Close()

	// Consider anything in 2xx range as success
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(postResp.Body)
		return fmt.Errorf("webhook endpoint returned error. Status: %d, Response: %s",
			postResp.StatusCode, string(bodyBytes))
	}

	return nil
}
