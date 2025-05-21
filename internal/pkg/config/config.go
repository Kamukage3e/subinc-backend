package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Config holds all configuration for the application
type Config struct {
	Database    DatabaseConfig
	Server      ServerConfig
	Redis       RedisConfig
	JWT         JWTConfig
	Stripe      StripeConfig
	PayPal      PayPalConfig
	Braintree   BraintreeConfig
	Logging     LoggingConfig
	Security    SecurityConfig
	Environment string // dev, staging, prod
	ServiceName string
	Version     string
}

// DatabaseConfig holds all database related configuration
type DatabaseConfig struct {
	Host           string
	Port           string
	User           string
	Password       string
	Database       string
	SSLMode        string
	MaxConnections int
	MaxIdleTime    time.Duration
}

// ServerConfig holds server related configuration
type ServerConfig struct {
	Port            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	AllowedOrigins  []string
	TrustedProxies  []string
}

// RedisConfig holds Redis related configuration
type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

// JWTConfig holds JWT related configuration
type JWTConfig struct {
	SecretName             string
	Secret                 string
	Issuer                 string
	ExpirationHours        int
	RefreshExpirationHours int
	HeaderName             string
	AllowedAlgorithms      []string
	VerifyIssuer           bool
	VerifySubject          bool
	VerifyExpiry           bool
}

// StripeConfig holds Stripe related configuration
type StripeConfig struct {
	APIKey         string
	WebhookSecret  string
	EndpointSecret string
}

// PayPalConfig holds PayPal related configuration
type PayPalConfig struct {
	ClientID     string
	ClientSecret string
	Environment  string // sandbox or live
}

// BraintreeConfig holds Braintree related configuration
type BraintreeConfig struct {
	MerchantID  string
	PublicKey   string
	PrivateKey  string
	Environment string // sandbox or production
}

// LoggingConfig holds logging related configuration
type LoggingConfig struct {
	Level  string
	Format string
	Color  bool
}

// SecurityConfig holds security related configuration
type SecurityConfig struct {
	PasswordMinLength int
	MFAEnabled        bool
	SessionTimeout    time.Duration
}

// LoadConfig loads configuration from environment variables
func LoadConfig(logger *logger.Logger) (*Config, error) {
	config := &Config{
		Environment: getEnv("APP_ENV", "dev"),
		ServiceName: getEnv("SERVICE_NAME", "subinc-backend"),
		Version:     getEnv("APP_VERSION", "0.1.0"),

		Database: DatabaseConfig{
			Host:           getEnv("DB_HOST", "localhost"),
			Port:           getEnv("DB_PORT", "5432"),
			User:           getEnv("DB_USER", "postgres"),
			Password:       getEnv("DB_PASSWORD", "postgres"),
			Database:       getEnv("DB_NAME", "subinc"),
			SSLMode:        getEnv("DB_SSLMODE", "disable"),
			MaxConnections: getEnvAsInt("DB_MAX_CONNECTIONS", 25),
			MaxIdleTime:    getEnvAsDuration("DB_MAX_IDLE_TIME", 15*time.Minute),
		},

		Server: ServerConfig{
			Port:            getEnv("PORT", "8080"),
			ReadTimeout:     getEnvAsDuration("SERVER_READ_TIMEOUT", 5*time.Second),
			WriteTimeout:    getEnvAsDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
			ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 20*time.Second),
			AllowedOrigins:  getEnvAsSlice("CORS_ALLOWED_ORIGINS", "*"),
			TrustedProxies:  getEnvAsSlice("TRUSTED_PROXIES", "127.0.0.1"),
		},

		Redis: RedisConfig{
			Address:  getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},

		JWT: JWTConfig{
			SecretName:             getEnv("JWT_SECRET_NAME", "jwt_secret"),
			Secret:                 getEnv("JWT_SECRET", "your-secret-key-here"),
			Issuer:                 getEnv("JWT_ISSUER", "subinc-backend"),
			ExpirationHours:        getEnvAsInt("JWT_EXPIRATION_HOURS", 24),
			RefreshExpirationHours: getEnvAsInt("JWT_REFRESH_EXPIRATION_HOURS", 168), // 7 days
			HeaderName:             getEnv("JWT_HEADER_NAME", "Authorization"),
			AllowedAlgorithms:      getEnvAsSlice("JWT_ALLOWED_ALGORITHMS", "HS256,HS384,HS512"),
			VerifyIssuer:           getEnvAsBool("JWT_VERIFY_ISSUER", true),
			VerifySubject:          getEnvAsBool("JWT_VERIFY_SUBJECT", false),
			VerifyExpiry:           getEnvAsBool("JWT_VERIFY_EXPIRY", true),
		},

		Stripe: StripeConfig{
			APIKey:         getEnv("STRIPE_API_KEY", ""),
			WebhookSecret:  getEnv("STRIPE_WEBHOOK_SECRET", ""),
			EndpointSecret: getEnv("STRIPE_ENDPOINT_SECRET", ""),
		},

		PayPal: PayPalConfig{
			ClientID:     getEnv("PAYPAL_CLIENT_ID", ""),
			ClientSecret: getEnv("PAYPAL_CLIENT_SECRET", ""),
			Environment:  getEnv("PAYPAL_ENVIRONMENT", "sandbox"),
		},

		Braintree: BraintreeConfig{
			MerchantID:  getEnv("BRAINTREE_MERCHANT_ID", ""),
			PublicKey:   getEnv("BRAINTREE_PUBLIC_KEY", ""),
			PrivateKey:  getEnv("BRAINTREE_PRIVATE_KEY", ""),
			Environment: getEnv("BRAINTREE_ENVIRONMENT", "sandbox"),
		},

		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
			Color:  getEnvAsBool("LOG_COLOR", false),
		},

		Security: SecurityConfig{
			PasswordMinLength: getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
			MFAEnabled:        getEnvAsBool("MFA_ENABLED", false),
			SessionTimeout:    getEnvAsDuration("SESSION_TIMEOUT", 24*time.Hour),
		},
	}

	if logger != nil {
		msg := fmt.Sprintf("Configuration loaded - env: %s, service: %s, version: %s",
			config.Environment, config.ServiceName, config.Version)
		logger.Info(msg)
	}

	return config, nil
}

// GetDatabaseDSN returns the PostgreSQL connection string
func (c *DatabaseConfig) GetDatabaseDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.Database, c.SSLMode)
}

// Helper functions to get environment variables with default values
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue string) []string {
	valueStr := getEnv(key, defaultValue)
	if valueStr == "" {
		return []string{}
	}
	return strings.Split(valueStr, ",")
}
