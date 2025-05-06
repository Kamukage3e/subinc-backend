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

// NewRouter creates a new router
func NewRouter(
	router fiber.Router,
	costService service.CostService,
	cloudProviderService service.CloudProviderService,
	billingService service.BillingService,
	couponService service.CouponService,
	optimizationService *service.OptimizationService,
	log *logger.Logger,
	secretsManager secrets.SecretsManager,
	jwtSecretName string,
) *Router {
	if log == nil {
		log = logger.NewNoop()
	}

	return &Router{
		router:               router,
		costService:          costService,
		cloudProviderService: cloudProviderService,
		billingService:       billingService,
		couponService:        couponService,
		optimizationService:  optimizationService,
		logger:               log,
		secretsManager:       secretsManager,
		jwtSecretName:        jwtSecretName,
	}
}

// SetupRoutes registers all API routes
func (r *Router) SetupRoutes() {
	// Register cost API routes
	costGroup := r.router.Group("/cost")

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
	billingGroup := r.router.Group("/billing",
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

	// Register anomaly routes
	costRepo := r.costService.(interface {
		Repo() repository.CostRepository
	}).Repo()
	anomalyService := service.NewAnomalyDetectionService(costRepo, r.logger)
	anomalyHandler := NewAnomalyHandler(anomalyService, r.logger)
	r.router.Post("/anomalies/detect", anomalyHandler.DetectAnomalies)
	r.router.Get("/anomalies", anomalyHandler.ListAnomalies)
	r.router.Get("/anomalies/:id/recommendation", anomalyHandler.GetRecommendation)

	// Register optimization routes
	optHandler := NewOptimizationHandler(r.optimizationService)
	opt := r.router.Group("/optimization", middleware.RBACMiddleware("admin", "owner", "user"))
	opt.Post("/recommendations", optHandler.GenerateRecommendations)
	opt.Get("/recommendations/:id", optHandler.GetRecommendation)
	opt.Get("/history", optHandler.ListHistory)
}

// RegisterBillingRoutes registers all billing endpoints on the given Fiber router group
func (h *BillingHandler) RegisterBillingRoutes(r fiber.Router) {
	r.Post("/accounts", middleware.RBACMiddleware("admin"), h.CreateAccount)
	r.Put("/accounts/:id", middleware.RBACMiddleware("admin"), h.UpdateAccount)
	r.Get("/accounts/:id", middleware.RBACMiddleware("admin", "user"), h.GetAccount)
	r.Get("/accounts", middleware.RBACMiddleware("admin", "user"), h.ListAccounts)

	r.Post("/plans", middleware.RBACMiddleware("admin"), h.CreatePlan)
	r.Put("/plans/:id", middleware.RBACMiddleware("admin"), h.UpdatePlan)
	r.Get("/plans/:id", middleware.RBACMiddleware("admin", "user"), h.GetPlan)
	r.Get("/plans", middleware.RBACMiddleware("admin", "user"), h.ListPlans)

	r.Post("/usage", middleware.RBACMiddleware("admin", "user"), h.CreateUsage)
	r.Get("/usage", middleware.RBACMiddleware("admin", "user"), h.ListUsage)

	r.Post("/invoices", middleware.RBACMiddleware("admin"), h.CreateInvoice)
	r.Put("/invoices/:id", middleware.RBACMiddleware("admin"), h.UpdateInvoice)
	r.Get("/invoices/:id", middleware.RBACMiddleware("admin", "user"), h.GetInvoice)
	r.Get("/invoices", middleware.RBACMiddleware("admin", "user"), h.ListInvoices)

	r.Post("/payments", middleware.RBACMiddleware("admin"), h.CreatePayment)
	r.Put("/payments/:id", middleware.RBACMiddleware("admin"), h.UpdatePayment)
	r.Get("/payments/:id", middleware.RBACMiddleware("admin", "user"), h.GetPayment)
	r.Get("/payments", middleware.RBACMiddleware("admin", "user"), h.ListPayments)

	r.Post("/audit-logs", middleware.RBACMiddleware("admin"), h.CreateAuditLog)
	r.Get("/audit-logs", middleware.RBACMiddleware("admin", "user"), h.ListAuditLogs)
	r.Get("/audit-logs/search", middleware.RBACMiddleware("admin"), h.SearchAuditLogs)

	r.Post("/discounts", middleware.RBACMiddleware("admin"), h.CreateDiscount)
	r.Put("/discounts/:id", middleware.RBACMiddleware("admin"), h.UpdateDiscount)
	r.Delete("/discounts/:id", middleware.RBACMiddleware("admin"), h.DeleteDiscount)
	r.Get("/discounts/:id", middleware.RBACMiddleware("admin", "user"), h.GetDiscount)
	r.Get("/discounts/code/:code", middleware.RBACMiddleware("admin", "user"), h.GetDiscountByCode)
	r.Get("/discounts", middleware.RBACMiddleware("admin", "user"), h.ListDiscounts)

	r.Post("/coupons", middleware.RBACMiddleware("admin"), h.CreateCoupon)
	r.Put("/coupons/:id", middleware.RBACMiddleware("admin"), h.UpdateCoupon)
	r.Delete("/coupons/:id", middleware.RBACMiddleware("admin"), h.DeleteCoupon)
	r.Get("/coupons/:id", middleware.RBACMiddleware("admin", "user"), h.GetCoupon)
	r.Get("/coupons/code/:code", middleware.RBACMiddleware("admin", "user"), h.GetCouponByCode)
	r.Get("/coupons", middleware.RBACMiddleware("admin", "user"), h.ListCoupons)

	// Add CRUD handlers for Credit, Refund, PaymentMethod, Subscription, WebhookEvent, InvoiceAdjustment
	// Register all new handlers in RegisterBillingRoutes
	r.Post("/credits", middleware.RBACMiddleware("admin"), h.CreateCredit)
	r.Put("/credits/:id", middleware.RBACMiddleware("admin"), h.UpdateCredit)
	r.Delete("/credits/:id", middleware.RBACMiddleware("admin"), h.DeleteCredit)
	r.Get("/credits/:id", middleware.RBACMiddleware("admin", "user"), h.GetCredit)
	r.Get("/credits", middleware.RBACMiddleware("admin", "user"), h.ListCredits)

	r.Post("/refunds", middleware.RBACMiddleware("admin"), h.CreateRefund)
	r.Put("/refunds/:id", middleware.RBACMiddleware("admin"), h.UpdateRefund)
	r.Delete("/refunds/:id", middleware.RBACMiddleware("admin"), h.DeleteRefund)
	r.Get("/refunds/:id", middleware.RBACMiddleware("admin", "user"), h.GetRefund)
	r.Get("/refunds", middleware.RBACMiddleware("admin", "user"), h.ListRefunds)

	r.Post("/payment-methods", middleware.RBACMiddleware("admin"), h.CreatePaymentMethod)
	r.Put("/payment-methods/:id", middleware.RBACMiddleware("admin"), h.UpdatePaymentMethod)
	r.Delete("/payment-methods/:id", middleware.RBACMiddleware("admin"), h.DeletePaymentMethod)
	r.Get("/payment-methods/:id", middleware.RBACMiddleware("admin", "user"), h.GetPaymentMethod)
	r.Get("/payment-methods", middleware.RBACMiddleware("admin", "user"), h.ListPaymentMethods)

	r.Post("/subscriptions", middleware.RBACMiddleware("admin"), h.CreateSubscription)
	r.Put("/subscriptions/:id", middleware.RBACMiddleware("admin"), h.UpdateSubscription)
	r.Delete("/subscriptions/:id", middleware.RBACMiddleware("admin"), h.DeleteSubscription)
	r.Get("/subscriptions/:id", middleware.RBACMiddleware("admin", "user"), h.GetSubscription)
	r.Get("/subscriptions", middleware.RBACMiddleware("admin", "user"), h.ListSubscriptions)

	r.Post("/webhook-events", middleware.RBACMiddleware("admin"), h.CreateWebhookEvent)
	r.Put("/webhook-events/:id", middleware.RBACMiddleware("admin"), h.UpdateWebhookEvent)
	r.Delete("/webhook-events/:id", middleware.RBACMiddleware("admin"), h.DeleteWebhookEvent)
	r.Get("/webhook-events/:id", middleware.RBACMiddleware("admin", "user"), h.GetWebhookEvent)
	r.Get("/webhook-events", middleware.RBACMiddleware("admin", "user"), h.ListWebhookEvents)

	r.Post("/invoice-adjustments", middleware.RBACMiddleware("admin"), h.CreateInvoiceAdjustment)
	r.Put("/invoice-adjustments/:id", middleware.RBACMiddleware("admin"), h.UpdateInvoiceAdjustment)
	r.Delete("/invoice-adjustments/:id", middleware.RBACMiddleware("admin"), h.DeleteInvoiceAdjustment)
	r.Get("/invoice-adjustments/:id", middleware.RBACMiddleware("admin", "user"), h.GetInvoiceAdjustment)
	r.Get("/invoice-adjustments", middleware.RBACMiddleware("admin", "user"), h.ListInvoiceAdjustments)

	r.Patch("/credits/:id", middleware.RBACMiddleware("admin"), h.PatchCredit)
	r.Patch("/payment-methods/:id", middleware.RBACMiddleware("admin"), h.PatchPaymentMethod)
	r.Patch("/subscriptions/:id", middleware.RBACMiddleware("admin"), h.PatchSubscription)
	r.Post("/subscriptions/:id/change-plan", middleware.RBACMiddleware("admin"), h.ChangePlanSubscription)
	r.Post("/subscriptions/:id/cancel", middleware.RBACMiddleware("admin"), h.CancelSubscriptionNow)
	r.Post("/subscriptions/:id/resume", middleware.RBACMiddleware("admin"), h.ResumeSubscription)

	r.Post("/webhooks/:provider", h.ReceiveWebhook)
	r.Get("/accounts/:id/invoice-preview", middleware.RBACMiddleware("admin", "user"), h.GetInvoicePreview)

	r.Post("/coupons/:code/redeem", middleware.RBACMiddleware("admin", "user"), h.RedeemCoupon)

	r.Post("/subscriptions/:id/upgrade-now", middleware.RBACMiddleware("admin"), h.UpgradeNowSubscription)

	r.Post("/invoices/:id/apply-credits", middleware.RBACMiddleware("admin"), h.ApplyCreditsToInvoice)

	r.Get("/billing/config", middleware.RBACMiddleware("admin"), h.GetBillingConfig)
	r.Post("/billing/config", middleware.RBACMiddleware("admin"), h.SetBillingConfig)

	r.Post("/manual-adjustment", middleware.RBACMiddleware("admin"), h.CreateManualAdjustment)
	r.Post("/manual-refund", middleware.RBACMiddleware("admin"), h.CreateManualRefund)
	r.Post("/account-action", middleware.RBACMiddleware("admin"), h.PerformAccountAction)

}

// RegisterRoutes registers the cloud provider API routes
func (h *CloudHandler) RegisterRoutes(router fiber.Router) {
	cloudRouter := router.Group("/cloud")

	// Provider information routes
	cloudRouter.Get("/providers", h.ListProviders)
	cloudRouter.Get("/providers/:provider", h.GetProviderInfo)

	// Integration management routes
	cloudRouter.Post("/integrations", h.CreateIntegration)
	cloudRouter.Get("/integrations", h.ListIntegrations)
	cloudRouter.Get("/integrations/:id", h.GetIntegration)
	cloudRouter.Put("/integrations/:id", h.UpdateIntegration)
	cloudRouter.Delete("/integrations/:id", h.DeleteIntegration)
	cloudRouter.Post("/integrations/:id/validate", h.ValidateIntegration)

	// Account management routes
	cloudRouter.Get("/integrations/:id/accounts", h.ListAccounts)
	cloudRouter.Put("/integrations/:id/accounts/default", h.SetDefaultAccount)

	// Cost import routes
	cloudRouter.Post("/import", h.ImportCostData)
}

// RegisterRoutes registers all cost management routes
func (h *CostHandler) RegisterRoutes(router fiber.Router) {
	costs := router.Group("/costs")

	// Cost data endpoints
	costs.Get("/:id", h.GetCostByID)
	costs.Post("/query", h.QueryCosts)
	costs.Get("/summary", h.GetCostSummary)

	// Import endpoints
	imports := costs.Group("/imports")
	imports.Post("/", h.ImportCostData)
	imports.Get("/:id", h.GetCostImportStatus)
	imports.Get("/", h.ListCostImports)

	// Budget endpoints
	budgets := costs.Group("/budgets")
	budgets.Post("/", h.CreateBudget)
	budgets.Put("/:id", h.UpdateBudget)
	budgets.Delete("/:id", h.DeleteBudget)
	budgets.Get("/:id", h.GetBudgetByID)
	budgets.Get("/", h.ListBudgets)

	// Anomaly endpoints
	anomalies := costs.Group("/anomalies")
	anomalies.Get("/:id", h.GetAnomalyByID)
	anomalies.Put("/:id", h.UpdateAnomaly)
	anomalies.Get("/", h.ListAnomalies)
	anomalies.Post("/detect", h.DetectAnomalies)

	// Forecast endpoints
	forecasts := costs.Group("/forecasts")
	forecasts.Post("/", h.GenerateForecast)
	forecasts.Get("/", h.GetForecast)
}
