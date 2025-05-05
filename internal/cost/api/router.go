package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/enterprise/notifications"
	"github.com/subinc/subinc-backend/internal/cost/middleware"
	"github.com/subinc/subinc-backend/internal/cost/repository"
	"github.com/subinc/subinc-backend/internal/cost/service"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/secrets"
)

// Router sets up all API routes
type Router struct {
	app                  *fiber.App
	costService          service.CostService
	cloudProviderService service.CloudProviderService
	billingService       service.BillingService
	couponService        service.CouponService
	logger               *logger.Logger
	secretsManager       secrets.SecretsManager
	jwtSecretName        string
}

// NewRouter creates a new router
func NewRouter(
	app *fiber.App,
	costService service.CostService,
	cloudProviderService service.CloudProviderService,
	billingService service.BillingService,
	couponService service.CouponService,
	log *logger.Logger,
	secretsManager secrets.SecretsManager,
	jwtSecretName string,
) *Router {
	if log == nil {
		log = logger.NewNoop()
	}

	return &Router{
		app:                  app,
		costService:          costService,
		cloudProviderService: cloudProviderService,
		billingService:       billingService,
		couponService:        couponService,
		logger:               log,
		secretsManager:       secretsManager,
		jwtSecretName:        jwtSecretName,
	}
}

// SetupRoutes registers all API routes
func (r *Router) SetupRoutes() {
	// Create API group
	api := r.app.Group("/api")

	// Register cost API routes
	costGroup := api.Group("/cost")

	// Register cost data routes
	costHandler := NewCostHandler(r.costService, r.logger)
	costHandler.RegisterRoutes(costGroup)

	// Register cloud provider routes
	cloudHandler := NewCloudHandler(r.cloudProviderService, r.logger)
	cloudHandler.RegisterRoutes(costGroup)

	// Register billing routes with logging, rate limit, and auth middleware
	providerRegistry := service.NewDefaultTokenizationProviderRegistry(r.logger)
	// Get the DB pool from the billing repo (assumes Repo() returns *pgxpool.Pool or similar)
	billingRepo := r.billingService.(interface {
		Repo() repository.BillingRepository
	}).Repo()
	var dbPool *pgxpool.Pool
	if pooler, ok := billingRepo.(interface{ DB() *pgxpool.Pool }); ok {
		dbPool = pooler.DB()
	}
	if dbPool == nil {
		panic("BillingRepository does not expose DB pool for NotificationStore")
	}
	notifStore := notifications.NewPostgresNotificationStore(dbPool, r.logger)
	billingGroup := api.Group("/billing",
		middleware.LoggingMiddleware(),
		middleware.RateLimitMiddleware(),
		middleware.AuthMiddleware(middleware.AuthMiddlewareConfig{
			SecretsManager: r.secretsManager,
			JWTSecretName:  r.jwtSecretName,
		}),
	)
	billingHandler := NewBillingHandler(
		r.billingService,
		r.couponService,
		service.NewCreditService(billingRepo, r.logger),
		service.NewRefundService(billingRepo, r.logger),
		service.NewPaymentMethodService(billingRepo, r.logger, providerRegistry),
		service.NewSubscriptionService(billingRepo, r.logger, notifStore),
		service.NewWebhookEventService(billingRepo, r.logger),
		service.NewInvoiceAdjustmentService(billingRepo, r.logger),
		r.logger,
	)
	billingHandler.RegisterBillingRoutes(billingGroup)

	// Register health check routes
	r.setupHealthCheck(api)

	// Register anomaly routes
	costRepo := r.costService.(interface {
		Repo() repository.CostRepository
	}).Repo()
	anomalyService := service.NewAnomalyDetectionService(costRepo, r.logger)
	anomalyHandler := NewAnomalyHandler(anomalyService, r.logger)
	apiV1 := api.Group("/v1")
	apiV1.Post("/anomalies/detect", anomalyHandler.DetectAnomalies)
	apiV1.Get("/anomalies", anomalyHandler.ListAnomalies)
	apiV1.Get("/anomalies/:id/recommendation", anomalyHandler.GetRecommendation)
}

// setupHealthCheck sets up health check routes
func (r *Router) setupHealthCheck(api fiber.Router) {
	// Health check endpoint
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "cost-management",
		})
	})
}
