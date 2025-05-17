package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/subinc/subinc-backend/internal/pkg/auth"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// Standard claim keys
const (
	ClaimUserID   = "user_id"
	ClaimTenantID = "tenant_id"
	ClaimEmail    = "email"
	ClaimRoles    = "roles"
	ClaimExp      = "exp"
	ClaimIat      = "iat"
	ClaimIss      = "iss"
	ClaimSub      = "sub"
)

// Config holds configuration for the JWT provider
type Config struct {
	// Secret is used to sign and verify tokens
	Secret string

	// Issuer identifies who created the token
	Issuer string

	// TokenExpiry is how long tokens are valid for
	TokenExpiry time.Duration

	// RefreshExpiry is how long refresh tokens are valid for
	RefreshExpiry time.Duration

	// Logger for logging errors and debugging info
	Logger *logger.Logger

	// HeaderName is the HTTP header to use for tokens
	HeaderName string

	// VerifyOptions specifies which claims to verify
	VerifyOptions VerifyOptions

	// AllowedAlgorithms specifies which signing algorithms are allowed
	AllowedAlgorithms []string
}

// VerifyOptions controls which claims are verified
type VerifyOptions struct {
	VerifyIssuer  bool
	VerifySubject bool
	VerifyExpiry  bool
}

// DefaultConfig returns a default JWT configuration
func DefaultConfig() Config {
	return Config{
		Secret:            "", // Must be set by user
		Issuer:            "subinc-backend",
		TokenExpiry:       24 * time.Hour,
		RefreshExpiry:     7 * 24 * time.Hour,
		HeaderName:        "Authorization",
		AllowedAlgorithms: []string{"HS256", "HS384", "HS512"},
		VerifyOptions: VerifyOptions{
			VerifyIssuer:  true,
			VerifySubject: false,
			VerifyExpiry:  true,
		},
	}
}

// JWTProvider implements the AuthProvider interface for JWT tokens
type JWTProvider struct {
	config Config
	logger *logger.Logger
}

// NewJWTProvider creates a new JWT auth provider with the given config
func NewJWTProvider(config Config) (*JWTProvider, error) {
	if config.Secret == "" {
		return nil, errors.New("jwt: secret cannot be empty")
	}

	if config.TokenExpiry <= 0 {
		config.TokenExpiry = 24 * time.Hour
	}

	if config.RefreshExpiry <= 0 {
		config.RefreshExpiry = 7 * 24 * time.Hour
	}

	if config.Logger == nil {
		config.Logger = logger.Default
	}

	if len(config.AllowedAlgorithms) == 0 {
		config.AllowedAlgorithms = []string{"HS256"}
	}

	return &JWTProvider{
		config: config,
		logger: config.Logger,
	}, nil
}

// Name returns the provider name
func (p *JWTProvider) Name() string {
	return "jwt"
}

// Version returns the provider version
func (p *JWTProvider) Version() string {
	return "1.0.0"
}

// GetCapabilities returns this provider's capabilities
func (p *JWTProvider) GetCapabilities() []auth.Capability {
	return []auth.Capability{
		auth.CapabilityStateless,
	}
}

// Authenticate validates credentials and returns user information
func (p *JWTProvider) Authenticate(ctx context.Context, credentials map[string]interface{}) (*auth.AuthResult, error) {
	// JWT provider does not directly authenticate credentials, it only verifies tokens
	// This would typically be used in conjunction with another provider that handles primary authentication
	return nil, auth.ErrUnsupportedOperation
}

// VerifyToken validates a JWT token and returns user information
func (p *JWTProvider) VerifyToken(ctx context.Context, tokenString string) (*auth.AuthResult, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing algorithm is allowed
		alg := token.Method.Alg()
		allowed := false
		for _, a := range p.config.AllowedAlgorithms {
			if a == alg {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				fmt.Sprintf("Unexpected JWT signing method: %v", token.Header["alg"]),
				"JWT_ALG_001",
				nil,
			)
		}

		return []byte(p.config.Secret), nil
	})

	if err != nil {
		p.logger.Warn("JWT validation failed",
			logger.String("error", err.Error()),
		)

		// Check for specific JWT error types and provide appropriate error responses
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				"JWT token has expired",
				"JWT_TOKEN_001",
				err,
			)
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				"JWT token not valid yet",
				"JWT_TOKEN_002",
				err,
			)
		} else if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				"JWT token is malformed",
				"JWT_TOKEN_003",
				err,
			)
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				"JWT token signature is invalid",
				"JWT_TOKEN_004",
				err,
			)
		}

		// General token error
		return nil, auth.NewAuthError(
			auth.ErrorTypeToken,
			"Invalid JWT token",
			"JWT_TOKEN_005",
			err,
		)
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Validate required claims
		if p.config.VerifyOptions.VerifyExpiry {
			// Check token expiration in jwt v5
			expClaim, ok := claims[ClaimExp]
			if !ok {
				return nil, auth.NewAuthError(
					auth.ErrorTypeToken,
					"JWT token missing expiration claim",
					"JWT_CLAIM_001",
					nil,
				)
			}

			var expTime time.Time
			switch exp := expClaim.(type) {
			case float64:
				expTime = time.Unix(int64(exp), 0)
			case json.Number:
				expInt, _ := exp.Int64()
				expTime = time.Unix(expInt, 0)
			default:
				return nil, auth.NewAuthError(
					auth.ErrorTypeToken,
					"JWT token has invalid expiration claim format",
					"JWT_CLAIM_002",
					nil,
				)
			}

			if time.Now().After(expTime) {
				return nil, auth.NewAuthError(
					auth.ErrorTypeToken,
					"JWT token has expired",
					"JWT_TOKEN_001",
					nil,
				)
			}
		}

		if p.config.VerifyOptions.VerifyIssuer {
			// Check issuer in jwt v5
			iss, ok := claims[ClaimIss].(string)
			if !ok || iss != p.config.Issuer {
				return nil, auth.NewAuthError(
					auth.ErrorTypeToken,
					"JWT token has invalid issuer",
					"JWT_CLAIM_003",
					nil,
				)
			}
		}

		userID, _ := claims[ClaimUserID].(string)
		if userID == "" {
			return nil, auth.NewAuthError(
				auth.ErrorTypeToken,
				"JWT token missing user_id claim",
				"JWT_CLAIM_004",
				nil,
			)
		}

		// Create auth result from claims
		result := &auth.AuthResult{
			UserID: userID,
			Claims: make(map[string]interface{}),
			Token: &auth.TokenInfo{
				Token:     tokenString,
				TokenType: "jwt",
				ExpiresAt: time.Unix(int64(claims[ClaimExp].(float64)), 0),
			},
		}

		// Populate optional fields if present
		if tenantID, ok := claims[ClaimTenantID].(string); ok {
			result.TenantID = tenantID
		}

		if email, ok := claims[ClaimEmail].(string); ok {
			result.Email = email
		}

		if rolesClaim, ok := claims[ClaimRoles]; ok {
			if rolesList, ok := rolesClaim.([]interface{}); ok {
				roles := make([]string, 0, len(rolesList))
				for _, r := range rolesList {
					if role, ok := r.(string); ok {
						roles = append(roles, role)
					}
				}
				result.Roles = roles
			}
		}

		// Store provider name in claims
		result.Claims["provider"] = p.Name()

		// Copy other non-standard claims
		for key, value := range claims {
			switch key {
			case ClaimUserID, ClaimTenantID, ClaimEmail, ClaimRoles, ClaimExp, ClaimIat, ClaimIss, ClaimSub:
				// Skip standard claims that are already processed
				continue
			default:
				result.Claims[key] = value
			}
		}

		return result, nil
	}

	return nil, auth.NewAuthError(
		auth.ErrorTypeToken,
		"JWT token has invalid format or claims",
		"JWT_TOKEN_006",
		nil,
	)
}

// RevokeToken invalidates a token
func (p *JWTProvider) RevokeToken(ctx context.Context, token string) error {
	// JWT tokens are stateless by default, so we can't technically "revoke" them
	// In a production environment, you would typically use a token blacklist or
	// a revocation store

	// This provider doesn't support revocation
	return auth.WrapError(
		errors.New("jwt: token revocation not supported by this provider"),
		auth.ErrorTypeProvider,
		"Token revocation not supported by JWT provider",
		"JWT_CAPABILITY_001",
	)
}

// RefreshToken validates a refresh token and issues a new access token
func (p *JWTProvider) RefreshToken(ctx context.Context, refreshToken string) (*auth.TokenInfo, error) {
	// Check if refresh token is empty
	if refreshToken == "" {
		return nil, auth.NewAuthError(
			auth.ErrorTypeValidation,
			"Refresh token cannot be empty",
			"JWT_REFRESH_001",
			nil,
		)
	}

	// Verify the refresh token
	result, err := p.VerifyToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Check if token is marked as a refresh token
	tokenType, _ := result.Claims["token_type"].(string)
	if tokenType != "refresh" {
		return nil, auth.NewAuthError(
			auth.ErrorTypeToken,
			"JWT token is not a refresh token",
			"JWT_REFRESH_002",
			nil,
		)
	}

	// Generate a new access token
	claims := jwt.MapClaims{
		ClaimUserID:   result.UserID,
		ClaimTenantID: result.TenantID,
		ClaimIss:      p.config.Issuer,
		ClaimIat:      time.Now().Unix(),
		ClaimExp:      time.Now().Add(p.config.TokenExpiry).Unix(),
		"token_type":  "access",
	}

	if result.Email != "" {
		claims[ClaimEmail] = result.Email
	}

	if len(result.Roles) > 0 {
		claims[ClaimRoles] = result.Roles
	}

	// Copy any other custom claims
	for key, value := range result.Claims {
		switch key {
		case ClaimUserID, ClaimTenantID, ClaimEmail, ClaimRoles, ClaimExp, ClaimIat, ClaimIss, ClaimSub, "provider", "token_type":
			// Skip standard claims
			continue
		default:
			claims[key] = value
		}
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to sign token: %w", err)
	}

	// Return the new token
	return &auth.TokenInfo{
		Token:     tokenString,
		TokenType: "jwt",
		ExpiresAt: time.Now().Add(p.config.TokenExpiry),
	}, nil
}

// GenerateToken creates a new JWT token with the given claims
func (p *JWTProvider) GenerateToken(userID, tenantID, email string, roles []string, customClaims map[string]interface{}) (*auth.TokenInfo, error) {
	// Create standard claims
	claims := jwt.MapClaims{
		ClaimUserID:   userID,
		ClaimTenantID: tenantID,
		ClaimIss:      p.config.Issuer,
		ClaimIat:      time.Now().Unix(),
		ClaimExp:      time.Now().Add(p.config.TokenExpiry).Unix(),
		"token_type":  "access",
	}

	if email != "" {
		claims[ClaimEmail] = email
	}

	if len(roles) > 0 {
		claims[ClaimRoles] = roles
	}

	// Add any custom claims
	for key, value := range customClaims {
		claims[key] = value
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to sign token: %w", err)
	}

	return &auth.TokenInfo{
		Token:     tokenString,
		TokenType: "jwt",
		ExpiresAt: time.Now().Add(p.config.TokenExpiry),
	}, nil
}

// GenerateRefreshToken creates a new refresh token
func (p *JWTProvider) GenerateRefreshToken(userID, tenantID string, customClaims map[string]interface{}) (*auth.TokenInfo, error) {
	// Create refresh token claims
	claims := jwt.MapClaims{
		ClaimUserID:   userID,
		ClaimTenantID: tenantID,
		ClaimIss:      p.config.Issuer,
		ClaimIat:      time.Now().Unix(),
		ClaimExp:      time.Now().Add(p.config.RefreshExpiry).Unix(),
		"token_type":  "refresh",
	}

	// Add any custom claims
	for key, value := range customClaims {
		claims[key] = value
	}

	// Create and sign the refresh token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(p.config.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: failed to sign refresh token: %w", err)
	}

	return &auth.TokenInfo{
		Token:     tokenString,
		TokenType: "refresh",
		ExpiresAt: time.Now().Add(p.config.RefreshExpiry),
	}, nil
}

// GenerateTokenPair creates both access and refresh tokens
func (p *JWTProvider) GenerateTokenPair(userID, tenantID, email string, roles []string, customClaims map[string]interface{}) (*auth.TokenInfo, *auth.TokenInfo, error) {
	// Generate access token
	accessToken, err := p.GenerateToken(userID, tenantID, email, roles, customClaims)
	if err != nil {
		return nil, nil, err
	}

	// Generate refresh token
	refreshToken, err := p.GenerateRefreshToken(userID, tenantID, customClaims)
	if err != nil {
		return nil, nil, err
	}

	// Link the tokens
	accessToken.RefreshToken = refreshToken.Token

	return accessToken, refreshToken, nil
}
