package billing_management

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	payment "github.com/subinc/subinc-backend/internal/admin/billing-management/payment"

	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	server_config "github.com/subinc/subinc-backend/internal/admin/server-config"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// SQL query constants
const (
	// Invoice queries
	QueryCreateInvoice = `INSERT INTO invoices (id, account_id, amount, status, due_date, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, account_id, amount, status, due_date, created_at, updated_at`

	QueryGetInvoice = `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE id = $1`

	QueryUpdateInvoice = `UPDATE invoices SET account_id = $2, amount = $3, status = $4, due_date = $5, updated_at = $6 
		WHERE id = $1 RETURNING id, account_id, amount, status, due_date, created_at, updated_at`

	QueryDeleteInvoice = `DELETE FROM invoices WHERE id = $1`

	QueryGetInvoicePreview = `SELECT id, account_id, amount, status, due_date, created_at, updated_at 
		FROM invoices WHERE account_id = $1 AND status = 'draft' ORDER BY created_at DESC LIMIT 1`

	// Invoice adjustments
	QueryApplyCreditsToInvoice = `UPDATE invoices SET amount = amount - (SELECT COALESCE(SUM(amount),0) 
		FROM credits WHERE invoice_id = $1 AND status = 'active'), updated_at = NOW() WHERE id = $1`

	// Billing config
	QueryGetBillingConfig = `SELECT key, value FROM billing_config`

	QuerySetBillingConfig = `INSERT INTO billing_config (key, value) VALUES ($1, $2) 
		ON CONFLICT (key) DO UPDATE SET value = $2`

	// Webhook subscriptions
	QueryCreateWebhookSubscription = `INSERT INTO webhook_subscriptions 
		(id, tenant_id, url, event_types, secret, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
		RETURNING id, tenant_id, url, event_types, secret, status, created_at, updated_at`

	QueryListWebhookSubscriptions = `SELECT id, tenant_id, url, event_types, secret, status, created_at, updated_at 
		FROM webhook_subscriptions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	QueryDeleteWebhookSubscription = `DELETE FROM webhook_subscriptions WHERE id = $1`

	QueryGetWebhookSubscription = `SELECT id, tenant_id, url, event_types, secret, status, created_at, updated_at 
		FROM webhook_subscriptions WHERE id = $1`

	QueryUpdateWebhookSubscription = `UPDATE webhook_subscriptions 
		SET url = $2, event_types = $3, secret = $4, status = $5, updated_at = $6 
		WHERE id = $1 RETURNING id, tenant_id, url, event_types, secret, status, created_at, updated_at`

	// Dunning queries
	QueryListInvoicesForDunning = `SELECT id, account_id, amount, status, due_date, created_at, updated_at, 
		dunning_attempts, dunning_next_attempt_at, dunning_status FROM invoices 
		WHERE dunning_status = 'active' AND dunning_next_attempt_at <= $1 
		AND dunning_attempts < $2 AND tenant_id = $3 LIMIT 100`

	QueryCreateDunningEvent = `INSERT INTO dunning_events 
		(id, invoice_id, event_type, status, details, created_at) 
		VALUES ($1, $2, $3, $4, $5, $6)`

	QueryListDunningEvents = `SELECT id, invoice_id, event_type, status, details, created_at 
		FROM dunning_events WHERE invoice_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	QueryGetDunningConfig = `SELECT max_attempts, retry_intervals FROM dunning_configs WHERE tenant_id = $1`

	QuerySetDunningConfig = `INSERT INTO dunning_configs (tenant_id, max_attempts, retry_intervals) 
		VALUES ($1, $2, $3) ON CONFLICT (tenant_id) DO UPDATE SET 
		max_attempts = $2, retry_intervals = $3`

	// Invoice dunning updating
	QueryUpdateInvoiceDunning = `UPDATE invoices SET 
		dunning_status = $1, 
		dunning_attempts = $2, 
		dunning_next_attempt_at = $3,
		updated_at = NOW()
		WHERE id = $4`

	// Exchange rate queries
	QueryGetExchangeRate = `SELECT id, base_currency, quote_currency, rate, source, updated_at 
		FROM exchange_rates WHERE base_currency = $1 AND quote_currency = $2`

	QueryUpdateExchangeRate = `UPDATE exchange_rates SET rate = $3, source = $4, updated_at = $5 
		WHERE base_currency = $1 AND quote_currency = $2 
		RETURNING id, base_currency, quote_currency, rate, source, updated_at`

	QueryDeleteExchangeRate = `DELETE FROM exchange_rates WHERE base_currency = $1 AND quote_currency = $2`

	QueryListExchangeRates = `SELECT id, base_currency, quote_currency, rate, source, updated_at 
		FROM exchange_rates ORDER BY base_currency, quote_currency`

	// Webhook delivery
	QueryRetryWebhookDelivery = `UPDATE webhook_delivery_logs 
		SET delivery_attempts = delivery_attempts + 1, 
		next_retry_at = NOW() + INTERVAL '1 hour', 
		updated_at = NOW() 
		WHERE id = $1`

	QueryListWebhookDeliveryLogs = `SELECT id, webhook_id, event_type, url, request_headers, 
		request_body, delivery_attempts, success, created_at, delivered_at, next_retry_at 
		FROM webhook_delivery_logs WHERE webhook_id = $1 
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	// Webhook event
	QueryListWebhookEvents = `SELECT id, provider, event_type, payload, status, received_at, processed_at, error, metadata 
		FROM webhook_events 
		WHERE account_id = $1 AND status = $2 ORDER BY received_at DESC LIMIT $3 OFFSET $4`

	QueryGetWebhookEvent = `SELECT id, provider, event_type, payload, status, received_at, processed_at, error, metadata
		FROM webhook_events WHERE id = $1`

	QueryCreateWebhookEvent = `INSERT INTO webhook_events 
		(id, provider, event_type, payload, status, received_at, metadata) 
		VALUES ($1, $2, $3, $4, $5, $6, $7) 
		RETURNING id, provider, event_type, payload, status, received_at, processed_at, error, metadata`

	QueryUpdateWebhookEvent = `UPDATE webhook_events 
		SET provider = $2, event_type = $3, payload = $4, status = $5, processed_at = $6, error = $7, metadata = $8 
		WHERE id = $1 
		RETURNING id, provider, event_type, payload, status, received_at, processed_at, error, metadata`

	QueryDeleteWebhookEvent = `DELETE FROM webhook_events WHERE id = $1`
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
	row := s.DB.QueryRow(ctx, QueryUpdateExchangeRate, rate.BaseCurrency, rate.QuoteCurrency, rate.Rate, rate.Source, rate.UpdatedAt)
	var out ExchangeRate
	if err := row.Scan(&out.ID, &out.BaseCurrency, &out.QuoteCurrency, &out.Rate, &out.Source, &out.UpdatedAt); err != nil {
		logger.LogError("UpdateExchangeRate failed", logger.ErrorField(err), logger.Any("rate", rate))
		return ExchangeRate{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteExchangeRate(ctx context.Context, base, quote string) error {
	_, err := s.DB.Exec(ctx, QueryDeleteExchangeRate, base, quote)
	if err != nil {
		logger.LogError("DeleteExchangeRate failed", logger.ErrorField(err), logger.String("base", base), logger.String("quote", quote))
		return err
	}
	return nil
}

func (s *PostgresStore) ListExchangeRates(ctx context.Context) ([]ExchangeRate, error) {
	rows, err := s.DB.Query(ctx, QueryListExchangeRates)
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
	row := s.DB.QueryRow(ctx, QueryGetExchangeRate, base, quote)
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

// --- ListInvoicesForDunning ---
func (s *PostgresStore) ListInvoicesForDunning(ctx context.Context, now time.Time, maxAttempts int, tenantID string) ([]Invoice, error) {
	rows, err := s.DB.Query(ctx, QueryListInvoicesForDunning, now, maxAttempts, tenantID)
	if err != nil {
		logger.LogError("ListInvoicesForDunning query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	var invoices []Invoice
	for rows.Next() {
		var i Invoice
		if err := rows.Scan(
			&i.ID, &i.AccountID, &i.Amount, &i.Status, &i.DueDate,
			&i.CreatedAt, &i.UpdatedAt, &i.DunningAttempts,
			&i.DunningNextAttemptAt, &i.DunningStatus); err != nil {
			logger.LogError("ListInvoicesForDunning scan failed", logger.ErrorField(err))
			return nil, err
		}
		invoices = append(invoices, i)
	}
	return invoices, nil
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

// CreateHMAC generates an HMAC signature for the given payload and secret
func CreateHMAC(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return fmt.Sprintf("sha256=%s", hex.EncodeToString(h.Sum(nil)))
}

// RunWebhookDeliveryWorker processes webhook delivery retries
func (s *PostgresStore) RunWebhookDeliveryWorker(ctx context.Context) {
	logger.LogInfo("WebhookDeliveryWorker: starting webhook delivery processing")

	// Query for webhook deliveries that need to be retried
	query := `SELECT id, webhook_id, event_type, url, request_headers, request_body, 
		delivery_attempts, created_at, next_retry_at 
		FROM webhook_delivery_logs 
		WHERE success = false AND next_retry_at <= NOW() 
		LIMIT 100`

	rows, err := s.DB.Query(ctx, query)
	if err != nil {
		logger.LogError("WebhookDeliveryWorker: query failed", logger.ErrorField(err))
		return
	}
	defer rows.Close()

	deliveriesToRetry := []WebhookDeliveryLog{}
	for rows.Next() {
		var log WebhookDeliveryLog
		if err := rows.Scan(
			&log.ID, &log.WebhookID, &log.EventType, &log.URL,
			&log.RequestHeaders, &log.RequestBody, &log.DeliveryAttempts,
			&log.CreatedAt, &log.NextRetryAt); err != nil {
			logger.LogError("WebhookDeliveryWorker: scan failed", logger.ErrorField(err))
			continue
		}
		deliveriesToRetry = append(deliveriesToRetry, log)
	}

	if len(deliveriesToRetry) == 0 {
		logger.LogInfo("WebhookDeliveryWorker: no webhook deliveries to retry")
		return
	}

	logger.LogInfo("WebhookDeliveryWorker: processing webhook deliveries",
		logger.Int("count", len(deliveriesToRetry)))

	// Process each delivery in parallel
	var wg sync.WaitGroup
	for _, delivery := range deliveriesToRetry {
		wg.Add(1)
		go func(log WebhookDeliveryLog) {
			defer wg.Done()

			// Get webhook subscription to check if it's still active
			var webhookStatus string
			err := s.DB.QueryRow(ctx,
				"SELECT status FROM webhook_subscriptions WHERE id = $1",
				log.WebhookID).Scan(&webhookStatus)

			if err != nil {
				logger.LogError("WebhookDeliveryWorker: failed to get webhook status",
					logger.ErrorField(err), logger.String("webhook_id", log.WebhookID))
				return
			}

			if webhookStatus != "active" {
				logger.LogInfo("WebhookDeliveryWorker: skipping inactive webhook",
					logger.String("webhook_id", log.WebhookID),
					logger.String("status", webhookStatus))
				return
			}

			// Retry webhook delivery
			err = s.RetryWebhookDelivery(ctx, log.ID)
			if err != nil {
				logger.LogError("WebhookDeliveryWorker: retry failed",
					logger.ErrorField(err), logger.String("delivery_id", log.ID))
			}
		}(delivery)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	logger.LogInfo("WebhookDeliveryWorker: completed webhook delivery processing")
}

// RetryWebhookDelivery attempts to retry a failed webhook delivery
func (s *PostgresStore) RetryWebhookDelivery(ctx context.Context, deliveryID string) error {
	const query = `
		SELECT id, webhook_id, event_type, url, request_headers, request_body, 
		delivery_attempts, success, created_at
		FROM webhook_delivery_logs 
		WHERE id = $1`

	var log WebhookDeliveryLog
	err := s.DB.QueryRow(ctx, query, deliveryID).Scan(
		&log.ID, &log.WebhookID, &log.EventType, &log.URL,
		&log.RequestHeaders, &log.RequestBody, &log.DeliveryAttempts,
		&log.Success, &log.CreatedAt)

	if err != nil {
		return err
	}

	// If already successful, no need to retry
	if log.Success {
		return nil
	}

	// Get the webhook subscription to retrieve the secret
	var secret string
	err = s.DB.QueryRow(ctx, "SELECT secret FROM webhook_subscriptions WHERE id = $1",
		log.WebhookID).Scan(&secret)

	if err != nil {
		return err
	}

	// Build headers for HTTP request
	headers := make(http.Header)
	headers.Add("Content-Type", "application/json")
	headers.Add("User-Agent", "SubInc-Webhook-Service/1.0")
	headers.Add("X-Webhook-ID", log.WebhookID)
	headers.Add("X-Webhook-Event", log.EventType)
	headers.Add("X-Webhook-Delivery", log.ID)
	headers.Add("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	// Generate HMAC signature for security
	signature := CreateHMAC([]byte(log.RequestBody), secret)
	headers.Add("X-Webhook-Signature", signature)

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", log.URL, bytes.NewBuffer([]byte(log.RequestBody)))
	if err != nil {
		failedAt := time.Now()
		return updateFailedDelivery(ctx, s, deliveryID, log.DeliveryAttempts+1, err.Error(), &failedAt)
	}

	// Set headers
	req.Header = headers

	// Send the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)

	// Handle HTTP error (connection issues, timeouts, etc.)
	if err != nil {
		failedAt := time.Now()
		return updateFailedDelivery(ctx, s, deliveryID, log.DeliveryAttempts+1, err.Error(), &failedAt)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		// Couldn't read body, but we did get a response
		respBody = []byte(fmt.Sprintf("Failed to read response body: %s", err.Error()))
	}

	// Process response
	respHeaders, _ := json.Marshal(resp.Header)

	// Check if it was successful (2xx status code)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Update as successful
		now := time.Now()
		_, err = s.DB.Exec(ctx, `
			UPDATE webhook_delivery_logs SET 
			success = true, 
			response_status = $1, 
			response_headers = $2, 
			response_body = $3, 
			delivered_at = $4,
			next_retry_at = NULL
			WHERE id = $5
		`, resp.StatusCode, string(respHeaders), string(respBody), now, deliveryID)

		if err != nil {
			return err
		}
		return nil
	}

	// If we get here, the delivery failed with a non-2xx status code
	failedAt := time.Now()
	errorMsg := fmt.Sprintf("HTTP status %d: %s", resp.StatusCode, string(respBody))

	// Store the response information even for failed deliveries
	_, err = s.DB.Exec(ctx, `
		UPDATE webhook_delivery_logs SET 
		response_status = $1, 
		response_headers = $2, 
		response_body = $3
		WHERE id = $4
	`, resp.StatusCode, string(respHeaders), string(respBody), deliveryID)

	if err != nil {
		logger.LogError("RetryWebhookDelivery: Failed to update response info", logger.ErrorField(err))
	}

	// Update the failure status and schedule next retry
	return updateFailedDelivery(ctx, s, deliveryID, log.DeliveryAttempts+1, errorMsg, &failedAt)
}

// updateFailedDelivery updates a webhook delivery log with failure information and schedules the next retry
func updateFailedDelivery(ctx context.Context, s *PostgresStore, deliveryID string, attempts int, errorMsg string, failedAt *time.Time) error {
	// Calculate next retry time using exponential backoff
	var nextRetry *time.Time

	if attempts < 10 { // Maximum 10 attempts
		// Exponential backoff with jitter: 2^n minutes + random 0-30 seconds
		delay := time.Duration(1<<uint(attempts-1)) * time.Minute
		jitter := time.Duration(30) * time.Second // Fixed jitter instead of random
		next := failedAt.Add(delay + jitter)
		nextRetry = &next
	}

	// Update delivery log with failure information
	_, err := s.DB.Exec(ctx, `
		UPDATE webhook_delivery_logs SET 
		delivery_attempts = $1, 
		error_message = $2, 
		last_retry_failed_at = $3,
		next_retry_at = $4
		WHERE id = $5
	`, attempts, errorMsg, failedAt, nextRetry, deliveryID)

	return err
}

// ListTenantsWithDunningConfig returns a list of tenant IDs that have dunning configuration set up
func (s *PostgresStore) ListTenantsWithDunningConfig(ctx context.Context) ([]string, error) {
	const q = `SELECT tenant_id FROM tenant_dunning_config WHERE max_attempts > 0`
	rows, err := s.DB.Query(ctx, q)
	if err != nil {
		logger.LogError("ListTenantsWithDunningConfig query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	var tenantIDs []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			logger.LogError("ListTenantsWithDunningConfig scan failed", logger.ErrorField(err))
			return nil, err
		}
		tenantIDs = append(tenantIDs, tenantID)
	}

	return tenantIDs, nil
}

// CreateDunningEvent creates a new dunning event
func (s *PostgresStore) CreateDunningEvent(ctx context.Context, event *DunningEvent) error {
	// Convert the details map to JSON string
	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		logger.LogError("CreateDunningEvent marshal failed", logger.ErrorField(err))
		return err
	}

	status := "pending" // Default status if not set
	if event.Status != "" {
		status = event.Status
	}

	q := QueryCreateDunningEvent
	_, err = s.DB.Exec(ctx, q,
		event.ID, event.InvoiceID, event.EventType,
		status, detailsJSON, event.CreatedAt)

	if err != nil {
		logger.LogError("CreateDunningEvent failed",
			logger.ErrorField(err),
			logger.String("event_id", event.ID))
		return err
	}

	return nil
}

// ListDunningEvents returns dunning events for an invoice
func (s *PostgresStore) ListDunningEvents(ctx context.Context, invoiceID string, page, pageSize int) ([]DunningEvent, error) {
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}

	q := QueryListDunningEvents
	rows, err := s.DB.Query(ctx, q, invoiceID, pageSize, offset)
	if err != nil {
		logger.LogError("ListDunningEvents query failed",
			logger.ErrorField(err),
			logger.String("invoice_id", invoiceID))
		return nil, err
	}
	defer rows.Close()

	var events []DunningEvent
	for rows.Next() {
		var e DunningEvent
		var detailsJSON []byte

		if err := rows.Scan(
			&e.ID, &e.InvoiceID, &e.EventType,
			&e.Status, &detailsJSON, &e.CreatedAt); err != nil {
			logger.LogError("ListDunningEvents scan failed", logger.ErrorField(err))
			return nil, err
		}

		// Parse the details JSON
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
				logger.LogError("ListDunningEvents unmarshal details failed",
					logger.ErrorField(err),
					logger.String("event_id", e.ID))
				// Continue with empty details rather than failing completely
				e.Details = make(map[string]interface{})
			}
		} else {
			e.Details = make(map[string]interface{})
		}

		events = append(events, e)
	}

	return events, nil
}

// GetDunningDashboard returns metrics and statistics about dunning
func (s *PostgresStore) GetDunningDashboard(ctx context.Context, tenantID string) (*DunningDashboard, error) {
	dashboard := &DunningDashboard{
		TenantID:     tenantID,
		GeneratedAt:  time.Now().UTC(),
		RecentEvents: make([]DunningEvent, 0),
	}

	// Get counts of invoices in dunning by status
	statusCountQuery := `
		SELECT dunning_status, COUNT(*) 
		FROM invoices 
		WHERE tenant_id = $1 AND dunning_status != '' 
		GROUP BY dunning_status
	`

	rows, err := s.DB.Query(ctx, statusCountQuery, tenantID)
	if err != nil {
		logger.LogError("GetDunningDashboard status count query failed",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			logger.LogError("GetDunningDashboard status count scan failed", logger.ErrorField(err))
			continue
		}

		switch status {
		case "active":
			dashboard.ActiveCount = count
		case "completed":
			dashboard.CompletedCount = count
		case "failed":
			dashboard.FailedCount = count
		case "paused":
			dashboard.PausedCount = count
		}
	}

	// Get total amount in dunning
	amountQuery := `
		SELECT COALESCE(SUM(amount), 0) 
		FROM invoices 
		WHERE tenant_id = $1 AND dunning_status = 'active'
	`

	err = s.DB.QueryRow(ctx, amountQuery, tenantID).Scan(&dashboard.TotalAmountInDunning)
	if err != nil {
		logger.LogError("GetDunningDashboard amount query failed",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		dashboard.TotalAmountInDunning = 0
	}

	// Get success rate
	successRateQuery := `
		SELECT 
			CASE 
				WHEN COUNT(*) = 0 THEN 0 
				ELSE ROUND((COUNT(*) FILTER (WHERE event_type = 'payment_success') * 100.0 / COUNT(*)), 2) 
			END
		FROM dunning_events 
		WHERE invoice_id IN (SELECT id FROM invoices WHERE tenant_id = $1)
	`

	err = s.DB.QueryRow(ctx, successRateQuery, tenantID).Scan(&dashboard.SuccessRate)
	if err != nil {
		logger.LogError("GetDunningDashboard success rate query failed",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		dashboard.SuccessRate = 0
	}

	// Get recent events
	recentEventsQuery := `
		SELECT e.id, e.invoice_id, e.event_type, e.status, e.details, e.created_at
		FROM dunning_events e
		JOIN invoices i ON e.invoice_id = i.id
		WHERE i.tenant_id = $1
		ORDER BY e.created_at DESC
		LIMIT 10
	`

	rows, err = s.DB.Query(ctx, recentEventsQuery, tenantID)
	if err != nil {
		logger.LogError("GetDunningDashboard recent events query failed",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		// Continue without recent events
	} else {
		defer rows.Close()
		for rows.Next() {
			var e DunningEvent
			var detailsJSON []byte

			if err := rows.Scan(
				&e.ID, &e.InvoiceID, &e.EventType,
				&e.Status, &detailsJSON, &e.CreatedAt); err != nil {
				logger.LogError("GetDunningDashboard events scan failed", logger.ErrorField(err))
				continue
			}

			// Parse the details JSON
			if len(detailsJSON) > 0 {
				if err := json.Unmarshal(detailsJSON, &e.Details); err != nil {
					e.Details = make(map[string]interface{})
				}
			} else {
				e.Details = make(map[string]interface{})
			}

			dashboard.RecentEvents = append(dashboard.RecentEvents, e)
		}
	}

	return dashboard, nil
}

// UpdateInvoiceDunning updates the dunning-related fields of an invoice
func (s *PostgresStore) UpdateInvoiceDunning(ctx context.Context, invoiceID, status string, attempts int, nextAttemptAt time.Time) error {
	if invoiceID == "" {
		return errors.New("invoice ID is required")
	}

	result, err := s.DB.Exec(ctx, QueryUpdateInvoiceDunning, status, attempts, nextAttemptAt, invoiceID)
	if err != nil {
		logger.LogError("UpdateInvoiceDunning failed",
			logger.ErrorField(err),
			logger.String("invoice_id", invoiceID),
			logger.String("status", status),
			logger.Int("attempts", attempts))
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("invoice not found: %s", invoiceID)
	}

	return nil
}

// SetDunningConfig sets the dunning configuration for a tenant
func (s *PostgresStore) SetDunningConfig(ctx context.Context, tenantID string, config *DunningConfig) error {
	if tenantID == "" {
		return errors.New("tenant ID is required")
	}

	if config == nil {
		return errors.New("dunning config is required")
	}

	// Validate config
	if config.MaxAttempts <= 0 {
		return errors.New("max_attempts must be greater than 0")
	}

	if len(config.RetryIntervals) == 0 {
		return errors.New("retry_intervals must not be empty")
	}

	// Convert retry intervals to JSON string
	intervals := make([]string, len(config.RetryIntervals))
	for i, d := range config.RetryIntervals {
		intervals[i] = d.String()
	}

	intervalsJSON, err := json.Marshal(intervals)
	if err != nil {
		return fmt.Errorf("failed to marshal retry intervals: %w", err)
	}

	// Insert or update dunning config
	_, err = s.DB.Exec(ctx, QuerySetDunningConfig,
		tenantID, config.MaxAttempts, string(intervalsJSON))

	if err != nil {
		logger.LogError("SetDunningConfig failed",
			logger.ErrorField(err),
			logger.String("tenant_id", tenantID))
		return err
	}

	return nil
}

// ListWebhookEvents retrieves a paginated list of webhook events
func (s *PostgresStore) ListWebhookEvents(ctx context.Context, accountID, status string, page, pageSize int) ([]WebhookEvent, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize

	rows, err := s.DB.Query(ctx, QueryListWebhookEvents, accountID, status, pageSize, offset)
	if err != nil {
		logger.LogError("ListWebhookEvents query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	var events []WebhookEvent
	for rows.Next() {
		var e WebhookEvent
		var processedAt sql.NullTime
		if err := rows.Scan(
			&e.ID, &e.Provider, &e.EventType, &e.Payload,
			&e.Status, &e.ReceivedAt, &processedAt, &e.Error, &e.Metadata); err != nil {
			logger.LogError("ListWebhookEvents scan failed", logger.ErrorField(err))
			return nil, err
		}

		if processedAt.Valid {
			e.ProcessedAt = &processedAt.Time
		}

		events = append(events, e)
	}

	return events, nil
}

// GetWebhookSubscription retrieves a webhook subscription by ID
func (s *PostgresStore) GetWebhookSubscription(ctx context.Context, id string) (WebhookSubscription, error) {
	row := s.DB.QueryRow(ctx, QueryGetWebhookSubscription, id)
	var out WebhookSubscription
	var eventTypes string

	if err := row.Scan(&out.ID, &out.TenantID, &out.URL, &eventTypes, &out.Secret, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		logger.LogError("GetWebhookSubscription failed", logger.ErrorField(err), logger.String("id", id))
		return WebhookSubscription{}, err
	}

	out.EventTypes = strings.Split(eventTypes, ",")
	return out, nil
}

// UpdateWebhookSubscription updates a webhook subscription
func (s *PostgresStore) UpdateWebhookSubscription(ctx context.Context, id string, url, secret string, events []string, status string) error {
	eventTypes := strings.Join(events, ",")
	updatedAt := time.Now().UTC()

	_, err := s.DB.Exec(ctx, QueryUpdateWebhookSubscription, id, url, eventTypes, secret, status, updatedAt)
	if err != nil {
		logger.LogError("UpdateWebhookSubscription failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}

	return nil
}

// TestWebhookSubscription tests a webhook subscription by sending a test event
func (s *PostgresStore) TestWebhookSubscription(ctx context.Context, id string, eventType string, payload map[string]interface{}) error {
	// First get the subscription to get the URL and secret
	sub, err := s.GetWebhookSubscription(ctx, id)
	if err != nil {
		return err
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		logger.LogError("TestWebhookSubscription marshal failed", logger.ErrorField(err))
		return err
	}

	// Create test event
	testEventID := fmt.Sprintf("test-%s", commonutil.GenerateUUID())

	// Build headers for HTTP request
	headers := make(http.Header)
	headers.Add("Content-Type", "application/json")
	headers.Add("User-Agent", "SubInc-Webhook-Service/1.0")
	headers.Add("X-Webhook-ID", id)
	headers.Add("X-Webhook-Event", eventType)
	headers.Add("X-Webhook-Delivery", testEventID)
	headers.Add("X-Webhook-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	headers.Add("X-Webhook-Test", "true")

	// Generate HMAC signature for security
	signature := CreateHMAC(payloadBytes, sub.Secret)
	headers.Add("X-Webhook-Signature", signature)

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", sub.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}

	// Set headers
	req.Header = headers

	// Send the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check if successful
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook test failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// GetWebhookDeliveryLogs retrieves delivery logs for a webhook subscription
func (s *PostgresStore) GetWebhookDeliveryLogs(ctx context.Context, subscriptionID string, page, pageSize int) ([]WebhookDeliveryLog, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize

	rows, err := s.DB.Query(ctx, QueryListWebhookDeliveryLogs, subscriptionID, pageSize, offset)
	if err != nil {
		logger.LogError("GetWebhookDeliveryLogs query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	var logs []WebhookDeliveryLog
	for rows.Next() {
		var log WebhookDeliveryLog
		var deliveredAt, nextRetryAt sql.NullTime

		if err := rows.Scan(
			&log.ID, &log.WebhookID, &log.EventType, &log.URL,
			&log.RequestHeaders, &log.RequestBody, &log.DeliveryAttempts,
			&log.Success, &log.CreatedAt, &deliveredAt, &nextRetryAt); err != nil {
			logger.LogError("GetWebhookDeliveryLogs scan failed", logger.ErrorField(err))
			return nil, err
		}

		if deliveredAt.Valid {
			log.DeliveredAt = &deliveredAt.Time
		}

		if nextRetryAt.Valid {
			log.NextRetryAt = &nextRetryAt.Time
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// CreateWebhookEvent creates a new webhook event
func (s *PostgresStore) CreateWebhookEvent(ctx context.Context, event WebhookEvent) (WebhookEvent, error) {
	row := s.DB.QueryRow(ctx, QueryCreateWebhookEvent,
		event.ID, event.Provider, event.EventType, event.Payload,
		event.Status, event.ReceivedAt, event.Metadata)

	var out WebhookEvent
	var processedAt sql.NullTime

	if err := row.Scan(
		&out.ID, &out.Provider, &out.EventType, &out.Payload,
		&out.Status, &out.ReceivedAt, &processedAt, &out.Error, &out.Metadata); err != nil {
		logger.LogError("CreateWebhookEvent failed", logger.ErrorField(err))
		return WebhookEvent{}, err
	}

	if processedAt.Valid {
		out.ProcessedAt = &processedAt.Time
	}

	return out, nil
}

// UpdateWebhookEvent updates an existing webhook event
func (s *PostgresStore) UpdateWebhookEvent(ctx context.Context, event WebhookEvent) (WebhookEvent, error) {
	var processedAt sql.NullTime
	if event.ProcessedAt != nil {
		processedAt = sql.NullTime{Time: *event.ProcessedAt, Valid: true}
	}

	row := s.DB.QueryRow(ctx, QueryUpdateWebhookEvent,
		event.ID, event.Provider, event.EventType, event.Payload,
		event.Status, processedAt, event.Error, event.Metadata)

	var out WebhookEvent
	var outProcessedAt sql.NullTime

	if err := row.Scan(
		&out.ID, &out.Provider, &out.EventType, &out.Payload,
		&out.Status, &out.ReceivedAt, &outProcessedAt, &out.Error, &out.Metadata); err != nil {
		logger.LogError("UpdateWebhookEvent failed", logger.ErrorField(err))
		return WebhookEvent{}, err
	}

	if outProcessedAt.Valid {
		out.ProcessedAt = &outProcessedAt.Time
	}

	return out, nil
}

// DeleteWebhookEvent deletes a webhook event
func (s *PostgresStore) DeleteWebhookEvent(ctx context.Context, id string) error {
	result, err := s.DB.Exec(ctx, QueryDeleteWebhookEvent, id)
	if err != nil {
		logger.LogError("DeleteWebhookEvent failed", logger.ErrorField(err))
		return err
	}

	if result.RowsAffected() == 0 {
		return NewNotFoundError("webhook event")
	}

	return nil
}

// GetWebhookEvent retrieves a webhook event by ID
func (s *PostgresStore) GetWebhookEvent(ctx context.Context, id string) (WebhookEvent, error) {
	row := s.DB.QueryRow(ctx, QueryGetWebhookEvent, id)

	var out WebhookEvent
	var processedAt sql.NullTime

	if err := row.Scan(
		&out.ID, &out.Provider, &out.EventType, &out.Payload,
		&out.Status, &out.ReceivedAt, &processedAt, &out.Error, &out.Metadata); err != nil {
		logger.LogError("GetWebhookEvent failed", logger.ErrorField(err))
		return WebhookEvent{}, err
	}

	if processedAt.Valid {
		out.ProcessedAt = &processedAt.Time
	}

	return out, nil
}

// DownloadInvoicePDF generates and returns a PDF for an invoice
func (s *PostgresStore) DownloadInvoicePDF(ctx context.Context, invoiceID string) ([]byte, error) {
	// Get the invoice
	invoice, err := s.GetInvoice(ctx, invoiceID)
	if err != nil {
		logger.LogError("DownloadInvoicePDF: failed to get invoice", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, err
	}

	// Ideally, this would use a PDF generation library or an external service
	// For now, we're generating a simple PDF representation
	var pdfContent bytes.Buffer
	pdfContent.WriteString(fmt.Sprintf("Invoice PDF for: %s\n", invoice.ID))
	pdfContent.WriteString(fmt.Sprintf("Account: %s\n", invoice.AccountID))
	pdfContent.WriteString(fmt.Sprintf("Amount: %.2f\n", invoice.Amount))
	pdfContent.WriteString(fmt.Sprintf("Status: %s\n", invoice.Status))
	pdfContent.WriteString(fmt.Sprintf("Due Date: %s\n", invoice.DueDate.Format("2006-01-02")))
	pdfContent.WriteString(fmt.Sprintf("Created At: %s\n", invoice.CreatedAt.Format("2006-01-02 15:04:05")))

	// In a production environment, we would use a PDF library such as fpdf or gofpdf
	// to generate a properly formatted PDF

	return pdfContent.Bytes(), nil
}

// --- Plugin System ---

// pluginRegistry keeps track of registered plugins
var pluginRegistry = struct {
	sync.RWMutex
	plugins map[string]map[string]interface{} // map[pluginType]map[pluginName]plugin
}{
	plugins: make(map[string]map[string]interface{}),
}

// ListPlugins lists all plugins of a specific type
func (s *PostgresStore) ListPlugins(ctx context.Context, pluginType string) ([]string, error) {
	pluginRegistry.RLock()
	defer pluginRegistry.RUnlock()

	if plugins, ok := pluginRegistry.plugins[pluginType]; ok {
		names := make([]string, 0, len(plugins))
		for name := range plugins {
			names = append(names, name)
		}
		return names, nil
	}

	return []string{}, nil
}

// GetPlugin retrieves a specific plugin
func (s *PostgresStore) GetPlugin(ctx context.Context, pluginType, name string) (interface{}, error) {
	pluginRegistry.RLock()
	defer pluginRegistry.RUnlock()

	if plugins, ok := pluginRegistry.plugins[pluginType]; ok {
		if plugin, ok := plugins[name]; ok {
			return plugin, nil
		}
	}

	return nil, fmt.Errorf("plugin not found: %s/%s", pluginType, name)
}

// RegisterPlugin registers a plugin
func (s *PostgresStore) RegisterPlugin(ctx context.Context, pluginType, name string, plugin interface{}) error {
	pluginRegistry.Lock()
	defer pluginRegistry.Unlock()

	if _, ok := pluginRegistry.plugins[pluginType]; !ok {
		pluginRegistry.plugins[pluginType] = make(map[string]interface{})
	}

	pluginRegistry.plugins[pluginType][name] = plugin
	logger.LogInfo("Registered plugin",
		logger.String("type", pluginType),
		logger.String("name", name))

	return nil
}

// UnregisterPlugin unregisters a plugin
func (s *PostgresStore) UnregisterPlugin(ctx context.Context, pluginType, name string) error {
	pluginRegistry.Lock()
	defer pluginRegistry.Unlock()

	if plugins, ok := pluginRegistry.plugins[pluginType]; ok {
		if _, exists := plugins[name]; exists {
			delete(plugins, name)
			logger.LogInfo("Unregistered plugin",
				logger.String("type", pluginType),
				logger.String("name", name))
			return nil
		}
	}

	return fmt.Errorf("plugin not found: %s/%s", pluginType, name)
}

// ConfigurePlugin configures a plugin
func (s *PostgresStore) ConfigurePlugin(ctx context.Context, pluginType, name string, config map[string]interface{}) error {
	plugin, err := s.GetPlugin(ctx, pluginType, name)
	if err != nil {
		return err
	}

	// Check if plugin implements a Configurable interface
	// This is a basic example - in a real system, we would have a proper plugin interface
	if configurable, ok := plugin.(interface {
		Configure(map[string]interface{}) error
	}); ok {
		return configurable.Configure(config)
	}

	// Store configuration in the database
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	const q = `INSERT INTO plugin_configs (plugin_type, plugin_name, config, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (plugin_type, plugin_name) DO UPDATE
		SET config = $3, updated_at = $4`

	_, err = s.DB.Exec(ctx, q, pluginType, name, string(configJSON), time.Now().UTC())
	return err
}

// DisablePlugin disables a plugin for a tenant
func (s *PostgresStore) DisablePlugin(ctx context.Context, pluginType, name, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant ID is required")
	}

	const q = `INSERT INTO disabled_plugins (tenant_id, plugin_type, plugin_name, disabled_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, plugin_type, plugin_name) DO NOTHING`

	_, err := s.DB.Exec(ctx, q, tenantID, pluginType, name, time.Now().UTC())
	return err
}
