package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// Extract all config values (example subset, expand as needed)
	appEnv := viper.GetString("APP_ENV")
	serverPort := viper.GetInt("server.port")
	// serverReadTimeout := viper.GetDuration("server.read_timeout")
	// serverWriteTimeout := viper.GetDuration("server.write_timeout")
	// serverIdleTimeout := viper.GetDuration("server.idle_timeout")
	maxHeaderBytes := viper.GetInt("server.max_header_bytes")
	jobsEnabled := viper.GetBool("server.jobs_enabled")

	dbURL := viper.GetString("database.url")
	dbDSN := viper.GetString("database.dsn")
	dbMaxOpenConns := viper.GetInt("database.max_open_conns")
	dbMaxIdleConns := viper.GetInt("database.max_idle_conns")
	dbConnMaxLifetime := viper.GetDuration("database.conn_max_lifetime")

	redisHost := viper.GetString("redis.host")
	redisPort := viper.GetInt("redis.port")
	redisPassword := viper.GetString("redis.password")
	redisDB := viper.GetInt("redis.db")
	redisPoolSize := viper.GetInt("redis.pool_size")
	redisMinIdleConns := viper.GetInt("redis.min_idle_conns")
	redisDialTimeout := viper.GetDuration("redis.dial_timeout")
	redisReadTimeout := viper.GetDuration("redis.read_timeout")
	redisWriteTimeout := viper.GetDuration("redis.write_timeout")

	logLevel := viper.GetString("logging.level")
	logFormat := viper.GetString("logging.format")
	logColor := viper.GetBool("logging.color")
	logService := viper.GetString("logging.service")
	logEnv := viper.GetString("logging.environment")

	awsRegion := viper.GetString("aws.region")
	awsCostRole := viper.GetString("aws.cost_explorer_role_arn")
	awsAccessKey := viper.GetString("aws.access_key_id")
	awsSecret := viper.GetString("aws.secret_access_key")
	awsSession := viper.GetString("aws.session_token")
	awsAccount := viper.GetString("aws.account_id")

	apiPrefix := viper.GetString("api.prefix")
	cloudDisableSecretManager := viper.GetBool("cloud.disableSecretManager")
	jwtSecretName := viper.GetString("jwt.secret_name")
	sessionPrefix := viper.GetString("session.prefix")
	sessionTTL := viper.GetDuration("session.ttl")

	rateLimitEnabled := viper.GetBool("rate_limit.enabled")
	rateLimitMaxRequests := viper.GetInt("rate_limit.max_requests")
	rateLimitWindow := viper.GetDuration("rate_limit.window")

	corsOrigins := viper.GetString("cors.origins")
	corsMethods := viper.GetString("cors.methods")
	corsHeaders := viper.GetString("cors.headers")
	corsAllowCredentials := viper.GetBool("cors.allow_credentials")

	billingTaxRate := viper.GetFloat64("billing.tax_rate")
	billingFixedFee := viper.GetFloat64("billing.fixed_fee")
	billingPercentFee := viper.GetFloat64("billing.percent_fee")

	stripeAPIKey := viper.GetString("payment.stripe_api_key")
	paypalClientID := viper.GetString("payment.paypal_client_id")
	paypalClientSecret := viper.GetString("payment.paypal_client_secret")
	googlePayMerchantID := viper.GetString("payment.googlepay_merchant_id")
	googlePayAPIKey := viper.GetString("payment.googlepay_api_key")
	applePayMerchantID := viper.GetString("payment.applepay_merchant_id")
	applePayAPIKey := viper.GetString("payment.applepay_api_key")
	paymentsDisabled := viper.GetBool("payment.payments_disabled")

	openaiAPIKey := viper.GetString("openai.api_key")
	openaiAPIURL := viper.GetString("openai.api_url")
	openaiModel := viper.GetString("openai.model")

	webhookEventsURL := viper.GetString("webhook.events_url")
	hashidSalt := viper.GetString("hashid_salt")
	goEnv := viper.GetString("go_env")
	adminEmail := viper.GetString("admin.email")
	adminUsername := viper.GetString("admin.username")
	adminPassword := viper.GetString("admin.password")

	// Print config summary for debug
	fmt.Printf("Loaded config: env=%s, db=%s, redis=%s:%d, serverPort=%d\n", appEnv, dbURL, redisHost, redisPort, serverPort)

	// Example: pass config to Fiber app (expand as needed)
	app := fiber.New()
	// ... inject config into handlers, jobs, logger, etc
	_ = app
	_ = logLevel
	_ = jobsEnabled
	_ = maxHeaderBytes
	_ = dbDSN
	_ = dbMaxOpenConns
	_ = dbMaxIdleConns
	_ = dbConnMaxLifetime
	_ = redisPassword
	_ = redisDB
	_ = redisPoolSize
	_ = redisMinIdleConns
	_ = redisDialTimeout
	_ = redisReadTimeout
	_ = redisWriteTimeout
	_ = logFormat
	_ = logColor
	_ = logService
	_ = logEnv
	_ = awsRegion
	_ = awsCostRole
	_ = awsAccessKey
	_ = awsSecret
	_ = awsSession
	_ = awsAccount
	_ = apiPrefix
	_ = cloudDisableSecretManager
	_ = jwtSecretName
	_ = sessionPrefix
	_ = sessionTTL
	_ = rateLimitEnabled
	_ = rateLimitMaxRequests
	_ = rateLimitWindow
	_ = corsOrigins
	_ = corsMethods
	_ = corsHeaders
	_ = corsAllowCredentials
	_ = billingTaxRate
	_ = billingFixedFee
	_ = billingPercentFee
	_ = stripeAPIKey
	_ = paypalClientID
	_ = paypalClientSecret
	_ = googlePayMerchantID
	_ = googlePayAPIKey
	_ = applePayMerchantID
	_ = applePayAPIKey
	_ = paymentsDisabled
	_ = openaiAPIKey
	_ = openaiAPIURL
	_ = openaiModel
	_ = webhookEventsURL
	_ = hashidSalt
	_ = goEnv
	_ = adminEmail
	_ = adminUsername
	_ = adminPassword

	// Start server (example, replace with real DI and startup)
	if err := app.Listen(fmt.Sprintf(":%d", serverPort)); err != nil {
		log.Fatalf("Fiber failed: %v", err)
	}
}
