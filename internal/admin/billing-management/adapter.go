package billing_management

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BillingAdapter provides adapter methods for billing management services
type BillingAdapter struct {
	db    *pgxpool.Pool
	store *PostgresStore
}

// NewBillingAdapter creates a new billing adapter instance
func NewBillingAdapter(db *pgxpool.Pool) *BillingAdapter {
	return &BillingAdapter{
		db:    db,
		store: NewPostgresStore(db, nil, nil),
	}
}

// Invoice operations

// CreateInvoice creates a new invoice in the system
func (a *BillingAdapter) CreateInvoice(ctx context.Context, invoice Invoice) (Invoice, error) {
	return a.store.CreateInvoice(ctx, invoice)
}

// GetInvoice retrieves an invoice by ID
func (a *BillingAdapter) GetInvoice(ctx context.Context, id string) (Invoice, error) {
	return a.store.GetInvoice(ctx, id)
}

// UpdateInvoice updates an existing invoice
func (a *BillingAdapter) UpdateInvoice(ctx context.Context, invoice Invoice) (Invoice, error) {
	return a.store.UpdateInvoice(ctx, invoice)
}

// ListInvoices retrieves a paginated list of invoices
func (a *BillingAdapter) ListInvoices(ctx context.Context, accountID, status string, page, pageSize int) ([]Invoice, error) {
	return a.store.ListInvoices(ctx, accountID, status, page, pageSize)
}

// DeleteInvoice removes an invoice from the system
func (a *BillingAdapter) DeleteInvoice(ctx context.Context, id string) error {
	return a.store.DeleteInvoice(ctx, id)
}

// GetInvoicePreview retrieves a draft invoice for preview
func (a *BillingAdapter) GetInvoicePreview(ctx context.Context, accountID string) (Invoice, error) {
	return a.store.GetInvoicePreview(ctx, accountID)
}

// GetBillingConfig retrieves billing configuration
func (a *BillingAdapter) GetBillingConfig(ctx context.Context) (map[string]interface{}, error) {
	return a.store.GetBillingConfig(ctx)
}

// SetBillingConfig updates billing configuration
func (a *BillingAdapter) SetBillingConfig(ctx context.Context, config map[string]interface{}) error {
	return a.store.SetBillingConfig(ctx, config)
}

// WebhookSubscription operations

// CreateWebhookSubscription creates a new webhook subscription
func (a *BillingAdapter) CreateWebhookSubscription(ctx context.Context, url, secret, description string, events []string) error {
	// Create a WebhookSubscription object
	sub := WebhookSubscription{
		ID:         generateUUID(),
		URL:        url,
		Secret:     secret,
		EventTypes: events,
		Status:     "active",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	// Store it using the PostgresStore
	_, err := a.store.CreateWebhookSubscription(ctx, sub)
	return err
}

// ListWebhookSubscriptions retrieves a paginated list of webhook subscriptions
func (a *BillingAdapter) ListWebhookSubscriptions(ctx context.Context, tenantID string, page, pageSize int) ([]WebhookSubscription, error) {
	return a.store.ListWebhookSubscriptions(ctx, tenantID, page, pageSize)
}

// DeleteWebhookSubscription removes a webhook subscription
func (a *BillingAdapter) DeleteWebhookSubscription(ctx context.Context, id string) error {
	return a.store.DeleteWebhookSubscription(ctx, id)
}

// GetWebhookSubscription retrieves a webhook subscription by ID
func (a *BillingAdapter) GetWebhookSubscription(ctx context.Context, id string) (WebhookSubscription, error) {
	// Implementation would call the corresponding store method
	return WebhookSubscription{}, ErrNotImplemented
}

// UpdateWebhookSubscription updates a webhook subscription
func (a *BillingAdapter) UpdateWebhookSubscription(ctx context.Context, id string, url, secret string, events []string, status string) error {
	// Implementation would call the corresponding store method
	return ErrNotImplemented
}

// TestWebhookSubscription tests a webhook subscription
func (a *BillingAdapter) TestWebhookSubscription(ctx context.Context, id string, eventType string, payload map[string]interface{}) error {
	// Implementation would call the corresponding store method
	return ErrNotImplemented
}

// GetWebhookDeliveryLogs retrieves delivery logs for a webhook subscription
func (a *BillingAdapter) GetWebhookDeliveryLogs(ctx context.Context, subscriptionID string, page, pageSize int) ([]WebhookDeliveryLog, error) {
	// Implementation would call the corresponding store method
	return nil, ErrNotImplemented
}

// RetryWebhookDelivery retries a failed webhook delivery
func (a *BillingAdapter) RetryWebhookDelivery(ctx context.Context, deliveryID string) error {
	return a.store.RetryWebhookDelivery(ctx, deliveryID)
}

// TenantCurrency operations

// SetTenantCurrency sets the default currency for a tenant
func (a *BillingAdapter) SetTenantCurrency(ctx context.Context, tenantID, currency string) (TenantCurrency, error) {
	return a.store.SetTenantCurrency(ctx, tenantID, currency)
}

// GetTenantCurrency retrieves the default currency for a tenant
func (a *BillingAdapter) GetTenantCurrency(ctx context.Context, tenantID string) (TenantCurrency, error) {
	return a.store.GetTenantCurrency(ctx, tenantID)
}

// InvoiceAdjustment operations

// CreateInvoiceAdjustment creates a new invoice adjustment
func (a *BillingAdapter) CreateInvoiceAdjustment(ctx context.Context, adjustment InvoiceAdjustment) (InvoiceAdjustment, error) {
	return a.store.CreateInvoiceAdjustment(ctx, adjustment)
}

// GetInvoiceAdjustment retrieves an invoice adjustment by ID
func (a *BillingAdapter) GetInvoiceAdjustment(ctx context.Context, id string) (InvoiceAdjustment, error) {
	return a.store.GetInvoiceAdjustment(ctx, id)
}

// UpdateInvoiceAdjustment updates an invoice adjustment
func (a *BillingAdapter) UpdateInvoiceAdjustment(ctx context.Context, adjustment InvoiceAdjustment) (InvoiceAdjustment, error) {
	return a.store.UpdateInvoiceAdjustment(ctx, adjustment)
}

// ListInvoiceAdjustments retrieves a paginated list of invoice adjustments
func (a *BillingAdapter) ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]InvoiceAdjustment, error) {
	return a.store.ListInvoiceAdjustments(ctx, invoiceID, adjType, page, pageSize)
}

// CreateManualAdjustment creates a manual adjustment for an invoice
func (a *BillingAdapter) CreateManualAdjustment(ctx context.Context, invoiceID, reason string, amount float64, currency string) error {
	// Implementation would create and store a manual adjustment
	return ErrNotImplemented
}

// ApplyCreditsToInvoice applies available credits to an invoice
func (a *BillingAdapter) ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error {
	return a.store.ApplyCreditsToInvoice(ctx, invoiceID)
}

// Exchange Rate operations

// CreateExchangeRate creates a new exchange rate
func (a *BillingAdapter) CreateExchangeRate(ctx context.Context, rate ExchangeRate) (ExchangeRate, error) {
	return a.store.CreateExchangeRate(ctx, rate)
}

// UpdateExchangeRate updates an exchange rate
func (a *BillingAdapter) UpdateExchangeRate(ctx context.Context, rate ExchangeRate) (ExchangeRate, error) {
	return a.store.UpdateExchangeRate(ctx, rate)
}

// GetExchangeRate retrieves an exchange rate
func (a *BillingAdapter) GetExchangeRate(ctx context.Context, base, quote string) (ExchangeRate, error) {
	return a.store.GetExchangeRate(ctx, base, quote)
}

// ListExchangeRates lists all exchange rates
func (a *BillingAdapter) ListExchangeRates(ctx context.Context) ([]ExchangeRate, error) {
	return a.store.ListExchangeRates(ctx)
}

// DeleteExchangeRate deletes an exchange rate
func (a *BillingAdapter) DeleteExchangeRate(ctx context.Context, base, quote string) error {
	return a.store.DeleteExchangeRate(ctx, base, quote)
}

// Report operations

// GetRevenueReport retrieves revenue report
func (a *BillingAdapter) GetRevenueReport(ctx context.Context) (map[string]interface{}, error) {
	return a.store.GetRevenueReport(ctx)
}

// GetARReport retrieves accounts receivable report
func (a *BillingAdapter) GetARReport(ctx context.Context) (map[string]interface{}, error) {
	return a.store.GetARReport(ctx)
}

// GetChurnReport retrieves churn report
func (a *BillingAdapter) GetChurnReport(ctx context.Context) (map[string]interface{}, error) {
	return a.store.GetChurnReport(ctx)
}

// Dunning operations

// GetDunningConfig retrieves dunning configuration for a tenant
func (a *BillingAdapter) GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error) {
	return a.store.GetDunningConfig(ctx, tenantID)
}

// SetDunningConfig sets dunning configuration for a tenant
func (a *BillingAdapter) SetDunningConfig(ctx context.Context, tenantID string, config *DunningConfig) error {
	return a.store.SetDunningConfig(ctx, tenantID, config)
}

// ListDunningEvents retrieves dunning events for an invoice
func (a *BillingAdapter) ListDunningEvents(ctx context.Context, invoiceID string, page, pageSize int) ([]DunningEvent, error) {
	return a.store.ListDunningEvents(ctx, invoiceID, page, pageSize)
}

// GetDunningDashboard retrieves a dunning dashboard for a tenant
func (a *BillingAdapter) GetDunningDashboard(ctx context.Context, tenantID string) (*DunningDashboard, error) {
	return a.store.GetDunningDashboard(ctx, tenantID)
}

// CreateDunningEvent creates a new dunning event
func (a *BillingAdapter) CreateDunningEvent(ctx context.Context, event *DunningEvent) error {
	return a.store.CreateDunningEvent(ctx, event)
}

// UpdateInvoiceDunning updates dunning-related fields for an invoice
func (a *BillingAdapter) UpdateInvoiceDunning(ctx context.Context, invoiceID, status string, attempts int, nextAttemptAt time.Time) error {
	return a.store.UpdateInvoiceDunning(ctx, invoiceID, status, attempts, nextAttemptAt)
}

// Generate a UUID (helper function)
func generateUUID() string {
	// This would normally call a proper UUID generator
	return "uuid-" + time.Now().Format(time.RFC3339)
}
