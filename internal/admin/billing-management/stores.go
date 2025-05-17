package billing_management

import (
	"context"

	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	payment "github.com/subinc/subinc-backend/internal/admin/billing-management/payment"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type DunningConfig = payment.DunningConfig

// --- Invoice CRUD ---
func (s *PostgresStore) CreateInvoice(ctx context.Context, i Invoice) (Invoice, error) {
	const q = `INSERT INTO invoices (id, account_id, amount, status, due_date, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, account_id, amount, status, due_date, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.CreatedAt, i.UpdatedAt)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreateInvoice failed", logger.ErrorField(err), logger.Any("invoice", i))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetInvoice(ctx context.Context, id string) (Invoice, error) {
	const q = `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			logger.LogWarn("GetInvoice: not found", logger.String("id", id))
			return Invoice{}, errors.New("no rows")
		}
		logger.LogError("GetInvoice failed", logger.ErrorField(err), logger.String("id", id))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateInvoice(ctx context.Context, i Invoice) (Invoice, error) {
	const q = `UPDATE invoices SET account_id = $2, amount = $3, status = $4, due_date = $5, updated_at = $6 WHERE id = $1 RETURNING id, account_id, amount, status, due_date, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.UpdatedAt)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateInvoice failed", logger.ErrorField(err), logger.Any("invoice", i))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListInvoices(ctx context.Context, accountID, status string, page, pageSize int) ([]Invoice, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE account_id = $1`
	args := []interface{}{accountID}
	if status != "" {
		q += " AND status = $2"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListInvoices query failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, err
	}
	defer rows.Close()
	var out []Invoice
	for rows.Next() {
		var i Invoice
		if err := rows.Scan(&i.ID, &i.AccountID, &i.Amount, &i.Status, &i.DueDate, &i.CreatedAt, &i.UpdatedAt); err != nil {
			logger.LogError("ListInvoices scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

func (s *PostgresStore) DeleteInvoice(ctx context.Context, id string) error {
	const q = `DELETE FROM invoices WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	return err
}

// --- GetInvoicePreview ---
func (s *PostgresStore) GetInvoicePreview(ctx context.Context, accountID string) (Invoice, error) {
	if accountID == "" {
		return Invoice{}, NewValidationError("account_id", "must not be empty")
	}
	const q = `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE account_id = $1 AND status = 'draft' ORDER BY created_at DESC LIMIT 1`
	row := s.DB.QueryRow(ctx, q, accountID)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("GetInvoicePreview failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return Invoice{}, err
	}
	return out, nil
}

// --- ApplyCreditsToInvoice ---
func (s *PostgresStore) ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error {
	if invoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	q := `UPDATE invoices SET amount = amount - (SELECT COALESCE(SUM(amount),0) FROM credits WHERE invoice_id = $1 AND status = 'active'), updated_at = NOW() WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, invoiceID)
	return err
}

// --- GetBillingConfig / SetBillingConfig ---
func (s *PostgresStore) GetBillingConfig(ctx context.Context) (map[string]interface{}, error) {
	const q = `SELECT key, value FROM billing_config`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("GetBillingConfig query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	config := make(map[string]interface{})
	for rows.Next() {
		var key string
		var value interface{}
		if err := rows.Scan(&key, &value); err != nil {
			logger.LogError("GetBillingConfig scan failed", logger.ErrorField(err))
			return nil, err
		}
		config[key] = value
	}
	return config, nil
}

func (s *PostgresStore) SetBillingConfig(ctx context.Context, input map[string]interface{}) error {
	for key, value := range input {
		q := `INSERT INTO billing_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`
		_, err := s.DB.Exec(ctx, q, key, value)
		if err != nil {
			logger.LogError("SetBillingConfig failed", logger.ErrorField(err), logger.String("key", key))
			return err
		}
	}
	return nil
}

// Implement WebhookSubscriptionService
func (s *PostgresStore) CreateWebhookSubscription(ctx context.Context, sub WebhookSubscription) (WebhookSubscription, error) {
	const q = `INSERT INTO webhook_subscriptions (id, tenant_id, url, event_types, secret, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, tenant_id, url, event_types, secret, status, created_at, updated_at`
	row := s.DB.QueryRow(ctx, q, sub.ID, sub.TenantID, sub.URL, strings.Join(sub.EventTypes, ","), sub.Secret, sub.Status, sub.CreatedAt, sub.UpdatedAt)
	var out WebhookSubscription
	var eventTypes string
	if err := row.Scan(&out.ID, &out.TenantID, &out.URL, &eventTypes, &out.Secret, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("CreateWebhookSubscription failed", logger.ErrorField(err), logger.Any("sub", sub))
		return WebhookSubscription{}, err
	}
	out.EventTypes = strings.Split(eventTypes, ",")
	return out, nil
}

func (s *PostgresStore) ListWebhookSubscriptions(ctx context.Context, tenantID string, page, pageSize int) ([]WebhookSubscription, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, url, event_types, secret, status, created_at, updated_at FROM webhook_subscriptions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := s.DB.Query(ctx, q, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("ListWebhookSubscriptions query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []WebhookSubscription
	for rows.Next() {
		var w WebhookSubscription
		var eventTypes string
		if err := rows.Scan(&w.ID, &w.TenantID, &w.URL, &eventTypes, &w.Secret, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			logger.LogError("ListWebhookSubscriptions scan failed", logger.ErrorField(err))
			return nil, err
		}
		w.EventTypes = strings.Split(eventTypes, ",")
		out = append(out, w)
	}
	return out, nil
}

func (s *PostgresStore) DeleteWebhookSubscription(ctx context.Context, subID string) error {
	const q = `DELETE FROM webhook_subscriptions WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, subID)
	return err
}

// --- Reporting ---
func (s *PostgresStore) GetRevenueReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.DB.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '30 days'`)
	var revenue float64
	if err := row.Scan(&revenue); err != nil {
		logger.LogError("GetRevenueReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"revenue": revenue}, nil
}

func (s *PostgresStore) GetARReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.DB.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status IN ('issued', 'overdue')`)
	var ar float64
	if err := row.Scan(&ar); err != nil {
		logger.LogError("GetARReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"accounts_receivable": ar}, nil
}

func (s *PostgresStore) GetChurnReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.DB.QueryRow(ctx, `SELECT COUNT(*) FROM subscriptions WHERE status = 'canceled' AND canceled_at >= NOW() - INTERVAL '30 days'`)
	var churn int
	if err := row.Scan(&churn); err != nil {
		logger.LogError("GetChurnReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"churned_subscriptions": churn}, nil
}

// --- Enhanced Invoice Creation: Fee/Tax Calculation ---
func (s *PostgresStore) CreateInvoiceWithFeesAndTax(ctx context.Context, i Invoice, fixedFee, percentFee, taxRate float64) (Invoice, error) {
	// Calculate subtotal
	subtotal := i.Amount
	feeTotal := fixedFee
	if percentFee > 0 {
		feeTotal += subtotal * (percentFee / 100)
	}
	taxAmount := (subtotal + feeTotal) * taxRate / 100
	i.TaxAmount = taxAmount
	i.TaxRate = taxRate
	i.Amount = subtotal + feeTotal + taxAmount
	// Store fees as JSON string for extensibility
	fees := []map[string]interface{}{}
	if fixedFee > 0 {
		fees = append(fees, map[string]interface{}{"type": "fixed", "amount": fixedFee})
	}
	if percentFee > 0 {
		fees = append(fees, map[string]interface{}{"type": "percent", "amount": percentFee})
	}
	feeBytes, _ := json.Marshal(fees)
	i.Fees = string(feeBytes)
	const q = `INSERT INTO invoices (id, account_id, amount, status, due_date, created_at, updated_at, tax_amount, tax_rate, fees) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, account_id, amount, status, due_date, created_at, updated_at, tax_amount, tax_rate, fees`
	row := s.DB.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.CreatedAt, i.UpdatedAt, i.TaxAmount, i.TaxRate, i.Fees)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt, &out.TaxAmount, &out.TaxRate, &out.Fees); err != nil {
		logger.LogError("CreateInvoiceWithFeesAndTax failed", logger.ErrorField(err), logger.Any("invoice", i))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) CreateExchangeRate(ctx context.Context, rate ExchangeRate) (ExchangeRate, error) {
	const q = `INSERT INTO exchange_rates (id, base_currency, quote_currency, rate, source, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (base_currency, quote_currency) DO UPDATE SET rate = $4, source = $5, updated_at = $6
		RETURNING id, base_currency, quote_currency, rate, source, updated_at`
	row := s.DB.QueryRow(ctx, q, rate.ID, rate.BaseCurrency, rate.QuoteCurrency, rate.Rate, rate.Source, rate.UpdatedAt)
	var out ExchangeRate
	if err := row.Scan(&out.ID, &out.BaseCurrency, &out.QuoteCurrency, &out.Rate, &out.Source, &out.UpdatedAt); err != nil {
		logger.LogError("CreateExchangeRate failed", logger.ErrorField(err), logger.Any("rate", rate))
		return ExchangeRate{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateExchangeRate(ctx context.Context, rate ExchangeRate) (ExchangeRate, error) {
	const q = `UPDATE exchange_rates SET rate = $3, source = $4, updated_at = $5 WHERE base_currency = $1 AND quote_currency = $2 RETURNING id, base_currency, quote_currency, rate, source, updated_at`
	row := s.DB.QueryRow(ctx, q, rate.BaseCurrency, rate.QuoteCurrency, rate.Rate, rate.Source, rate.UpdatedAt)
	var out ExchangeRate
	if err := row.Scan(&out.ID, &out.BaseCurrency, &out.QuoteCurrency, &out.Rate, &out.Source, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateExchangeRate failed", logger.ErrorField(err), logger.Any("rate", rate))
		return ExchangeRate{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteExchangeRate(ctx context.Context, base, quote string) error {
	const q = `DELETE FROM exchange_rates WHERE base_currency = $1 AND quote_currency = $2`
	_, err := s.DB.Exec(ctx, q, base, quote)
	if err != nil {
		logger.LogError("DeleteExchangeRate failed", logger.ErrorField(err), logger.String("base", base), logger.String("quote", quote))
		return err
	}
	return nil
}

func (s *PostgresStore) ListExchangeRates(ctx context.Context) ([]ExchangeRate, error) {
	const q = `SELECT id, base_currency, quote_currency, rate, source, updated_at FROM exchange_rates ORDER BY base_currency, quote_currency`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("ListExchangeRates query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeRate
	for rows.Next() {
		var r ExchangeRate
		if err := rows.Scan(&r.ID, &r.BaseCurrency, &r.QuoteCurrency, &r.Rate, &r.Source, &r.UpdatedAt); err != nil {
			logger.LogError("ListExchangeRates scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *PostgresStore) SetTenantCurrency(ctx context.Context, tenantID, currency string) (TenantCurrency, error) {
	if tenantID == "" {
		return TenantCurrency{}, NewValidationError("tenant_id", "must not be empty")
	}
	if len(currency) != 3 {
		return TenantCurrency{}, NewValidationError("currency", "must be ISO 4217 code")
	}
	currency = strings.ToUpper(currency)
	updatedAt := time.Now().UTC()
	const q = `INSERT INTO tenant_currency (tenant_id, currency, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET currency = $2, updated_at = $3
		RETURNING tenant_id, currency, updated_at`
	row := s.DB.QueryRow(ctx, q, tenantID, currency, updatedAt)
	var out TenantCurrency
	if err := row.Scan(&out.TenantID, &out.Currency, &out.UpdatedAt); err != nil {
		logger.LogError("SetTenantCurrency failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("currency", currency))
		return TenantCurrency{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetTenantCurrency(ctx context.Context, tenantID string) (TenantCurrency, error) {
	if tenantID == "" {
		return TenantCurrency{}, NewValidationError("tenant_id", "must not be empty")
	}
	const q = `SELECT tenant_id, currency, updated_at FROM tenant_currency WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var out TenantCurrency
	if err := row.Scan(&out.TenantID, &out.Currency, &out.UpdatedAt); err != nil {
		logger.LogError("GetTenantCurrency failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return TenantCurrency{}, err
	}
	return out, nil
}

// --- InvoiceAdjustment CRUD ---
func (s *PostgresStore) CreateInvoiceAdjustment(ctx context.Context, a InvoiceAdjustment) (InvoiceAdjustment, error) {
	const q = `INSERT INTO invoice_adjustments (id, invoice_id, type, amount, currency, original_amount, original_currency, reason, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, invoice_id, type, amount, currency, original_amount, original_currency, reason, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, a.ID, a.InvoiceID, a.Type, a.Amount, a.Currency, a.OriginalAmount, a.OriginalCurrency, a.Reason, a.CreatedAt, a.UpdatedAt, a.Metadata)
	var out InvoiceAdjustment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Type, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateInvoiceAdjustment failed", logger.ErrorField(err), logger.Any("adj", a))
		return InvoiceAdjustment{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetInvoiceAdjustment(ctx context.Context, id string) (InvoiceAdjustment, error) {
	const q = `SELECT id, invoice_id, type, amount, currency, original_amount, original_currency, reason, created_at, updated_at, metadata FROM invoice_adjustments WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out InvoiceAdjustment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Type, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("GetInvoiceAdjustment failed", logger.ErrorField(err), logger.String("id", id))
		return InvoiceAdjustment{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateInvoiceAdjustment(ctx context.Context, a InvoiceAdjustment) (InvoiceAdjustment, error) {
	const q = `UPDATE invoice_adjustments SET invoice_id = $2, type = $3, amount = $4, currency = $5, original_amount = $6, original_currency = $7, reason = $8, updated_at = $9, metadata = $10 WHERE id = $1
		RETURNING id, invoice_id, type, amount, currency, original_amount, original_currency, reason, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, a.ID, a.InvoiceID, a.Type, a.Amount, a.Currency, a.OriginalAmount, a.OriginalCurrency, a.Reason, a.UpdatedAt, a.Metadata)
	var out InvoiceAdjustment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Type, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdateInvoiceAdjustment failed", logger.ErrorField(err), logger.Any("adj", a))
		return InvoiceAdjustment{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListInvoiceAdjustments(ctx context.Context, invoiceID, adjType string, page, pageSize int) ([]InvoiceAdjustment, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, invoice_id, type, amount, currency, original_amount, original_currency, reason, created_at, updated_at, metadata FROM invoice_adjustments WHERE invoice_id = $1 AND type = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, q, invoiceID, adjType, pageSize, offset)
	if err != nil {
		logger.LogError("ListInvoiceAdjustments query failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, err
	}
	defer rows.Close()
	var out []InvoiceAdjustment
	for rows.Next() {
		var a InvoiceAdjustment
		if err := rows.Scan(&a.ID, &a.InvoiceID, &a.Type, &a.Amount, &a.Currency, &a.OriginalAmount, &a.OriginalCurrency, &a.Reason, &a.CreatedAt, &a.UpdatedAt, &a.Metadata); err != nil {
			logger.LogError("ListInvoiceAdjustments scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// GetDunningConfig returns the dunning configuration for a tenant. Not implemented yet.
func (s *PostgresStore) GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error) {
	if tenantID == "" {
		logger.LogError("GetDunningConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	const q = `
	SELECT max_attempts, retry_intervals_json FROM tenant_dunning_config WHERE tenant_id = $1
	`
	var maxAttempts int
	var retryIntervalsJSON string
	err := s.DB.QueryRow(ctx, q, tenantID).Scan(&maxAttempts, &retryIntervalsJSON)
	if err != nil {
		logger.LogError("GetDunningConfig: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to get dunning config")
	}
	var intervals []string
	err = json.Unmarshal([]byte(retryIntervalsJSON), &intervals)
	if err != nil {
		logger.LogError("GetDunningConfig: unmarshal intervals failed", logger.ErrorField(err))
		return nil, errors.New("invalid retry intervals")
	}
	var retryIntervals []time.Duration
	for _, s := range intervals {
		d, err := time.ParseDuration(s)
		if err != nil {
			logger.LogError("GetDunningConfig: parse duration failed", logger.ErrorField(err))
			continue
		}
		retryIntervals = append(retryIntervals, d)
	}
	return &DunningConfig{MaxAttempts: maxAttempts, RetryIntervals: retryIntervals}, nil
}

// GetPaymentResult implements payment.StoreInterface for provider compatibility.

func NewPostgresStore(db *pgxpool.Pool, serverConfigService *server_config.Service, auditLogger security_management.AuditLogger) *PostgresStore {
	if db == nil {
		panic("PostgresStore: DB must not be nil")
	}
	if serverConfigService == nil {
		panic("PostgresStore: ServerConfigService must not be nil (required for all secrets/keys)")
	}
	return &PostgresStore{
		DB:                  db,
		ServerConfigService: serverConfigService,
		AuditLogger:         auditLogger,
	}
}

func (s *PostgresStore) GetExchangeRate(ctx context.Context, base, quote string) (ExchangeRate, error) {
	const q = `SELECT id, base_currency, quote_currency, rate, source, updated_at FROM exchange_rates WHERE base_currency = $1 AND quote_currency = $2`
	row := s.DB.QueryRow(ctx, q, base, quote)
	var out ExchangeRate
	if err := row.Scan(&out.ID, &out.BaseCurrency, &out.QuoteCurrency, &out.Rate, &out.Source, &out.UpdatedAt); err != nil {
		logger.LogError("GetExchangeRate failed", logger.ErrorField(err), logger.String("base", base), logger.String("quote", quote))
		return ExchangeRate{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateInvoiceStatus(ctx context.Context, invoiceID, status string) error {
	if invoiceID == "" || status == "" {
		return errors.New("invoiceID and status required")
	}
	const q = `UPDATE invoices SET status = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, invoiceID, status)
	if err != nil {
		logger.LogError("UpdateInvoiceStatus failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID), logger.String("status", status))
		return err
	}
	if res.RowsAffected() == 0 {
		return errors.New("invoice not found")
	}
	return nil
}

func (s *PostgresStore) IsStripeEventProcessed(ctx context.Context, eventID string) (bool, error) {
	if eventID == "" {
		return false, errors.New("eventID required")
	}
	const q = `SELECT 1 FROM stripe_webhook_events WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, eventID)
	var exists int
	if err := row.Scan(&exists); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false, nil
		}
		logger.LogError("IsStripeEventProcessed failed", logger.ErrorField(err), logger.String("event_id", eventID))
		return false, err
	}
	return true, nil
}

func (s *PostgresStore) MarkStripeEventProcessed(ctx context.Context, eventID, eventType string) error {
	if eventID == "" {
		return errors.New("eventID required")
	}
	const q = `INSERT INTO stripe_webhook_events (id, type, processed_at) VALUES ($1, $2, NOW()) ON CONFLICT DO NOTHING`
	_, err := s.DB.Exec(ctx, q, eventID, eventType)
	if err != nil {
		logger.LogError("MarkStripeEventProcessed failed", logger.ErrorField(err), logger.String("event_id", eventID))
	}
	return err
}

func (s *PostgresStore) UpdateSubscriptionStatus(ctx context.Context, subscriptionID, status string) error {
	if subscriptionID == "" || status == "" {
		return errors.New("subscriptionID and status required")
	}
	const q = `UPDATE subscriptions SET status = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, subscriptionID, status)
	if err != nil {
		logger.LogError("UpdateSubscriptionStatus failed", logger.ErrorField(err), logger.String("subscription_id", subscriptionID), logger.String("status", status))
		return err
	}
	if res.RowsAffected() == 0 {
		return errors.New("subscription not found")
	}
	return nil
}

func (s *PostgresStore) ListInvoicesForDunning(ctx context.Context, now time.Time, maxAttempts int) ([]Invoice, error) {
	const q = `SELECT id, account_id, amount, status, due_date, created_at, updated_at, dunning_attempts, dunning_next_attempt_at, dunning_status FROM invoices WHERE status = 'payment_failed' AND dunning_status = 'active' AND dunning_attempts < $1 AND dunning_next_attempt_at <= $2`
	rows, err := s.DB.Query(ctx, q, maxAttempts, now)
	if err != nil {
		logger.LogError("ListInvoicesForDunning query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Invoice
	for rows.Next() {
		var i Invoice
		if err := rows.Scan(&i.ID, &i.AccountID, &i.Amount, &i.Status, &i.DueDate, &i.CreatedAt, &i.UpdatedAt, &i.DunningAttempts, &i.DunningNextAttemptAt, &i.DunningStatus); err != nil {
			logger.LogError("ListInvoicesForDunning scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

// --- InvoicePluginConfig CRUD ---
func (s *PostgresStore) SetInvoicePluginConfig(ctx context.Context, tenantID, pluginName string) (InvoicePluginConfig, error) {
	if tenantID == "" {
		return InvoicePluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		return InvoicePluginConfig{}, NewValidationError("plugin_name", "must not be empty")
	}
	updatedAt := time.Now().UTC()
	const q = `INSERT INTO invoice_plugin_config (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET plugin_name = $2, updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at`
	row := s.DB.QueryRow(ctx, q, tenantID, pluginName, updatedAt)
	var out InvoicePluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("SetInvoicePluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return InvoicePluginConfig{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetInvoicePluginConfig(ctx context.Context, tenantID string) (InvoicePluginConfig, error) {
	if tenantID == "" {
		return InvoicePluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	const q = `SELECT tenant_id, plugin_name, updated_at FROM invoice_plugin_config WHERE tenant_id = $1`
	row := s.DB.QueryRow(ctx, q, tenantID)
	var out InvoicePluginConfig
	if err := row.Scan(&out.TenantID, &out.PluginName, &out.UpdatedAt); err != nil {
		logger.LogError("GetInvoicePluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return InvoicePluginConfig{}, err
	}
	return out, nil
}

// DisableInvoicePluginConfig disables an invoice plugin for a tenant
func (s *PostgresStore) DisableInvoicePluginConfig(ctx context.Context, tenantID, pluginName string) error {
	if tenantID == "" || pluginName == "" {
		return NewValidationError("tenant_id/plugin_name", "must not be empty")
	}
	const q = `UPDATE invoice_plugin_config SET enabled = false, updated_at = $1 WHERE tenant_id = $2 AND plugin_name = $3`
	result, err := s.DB.Exec(ctx, q, time.Now().UTC(), tenantID, pluginName)
	if err != nil {
		logger.LogError("DisableInvoicePluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return err
	}
	if result.RowsAffected() == 0 {
		return NewNotFoundError("invoice plugin config")
	}
	return nil
}

// DisableTaxPluginConfig disables a tax plugin for a tenant
func (s *PostgresStore) DisableTaxPluginConfig(ctx context.Context, tenantID, pluginName string) error {
	if tenantID == "" || pluginName == "" {
		return NewValidationError("tenant_id/plugin_name", "must not be empty")
	}
	const q = `UPDATE tax_plugin_config SET enabled = false, updated_at = $1 WHERE tenant_id = $2 AND plugin_name = $3`
	result, err := s.DB.Exec(ctx, q, time.Now().UTC(), tenantID, pluginName)
	if err != nil {
		logger.LogError("DisableTaxPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return err
	}
	if result.RowsAffected() == 0 {
		return NewNotFoundError("tax plugin config")
	}
	return nil
}
