package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

type OIDCConfig struct {
	IssuerURL        string
	ClientID         string
	SecretsManager   secrets.SecretsManager
	ClientSecretName string // Name in secrets manager
}

func OIDCMiddleware(cfg OIDCConfig) (fiber.Handler, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid authorization header"})
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		idToken, err := verifier.Verify(c.Context(), tokenStr)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired OIDC token"})
		}
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid OIDC claims"})
		}
		c.Locals("claims", claims)
		return c.Next()
	}, nil
}
