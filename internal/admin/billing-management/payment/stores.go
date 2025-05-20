package payment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// --- SQL Query Constants ---
const (
	qCreateRefund = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata`
	qGetRefund    = `SELECT id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata FROM refunds WHERE id = $1`
	qUpdateRefund = `UPDATE refunds SET payment_id = $2, invoice_id = $3, amount = $4, currency = $5, original_amount = $6, original_currency = $7, reason = $8, status = $9, updated_at = $10, metadata = $11 WHERE id = $1
		RETURNING id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata`
	qListRefunds   = `SELECT id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata FROM refunds WHERE 1=1`
	qCreatePayment = `INSERT INTO payments (id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata`
	qGetPayment    = `SELECT id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata FROM payments WHERE id = $1`
	qUpdatePayment = `UPDATE payments SET invoice_id = $2, amount = $3, currency = $4, original_amount = $5, original_currency = $6, status = $7, method = $8, last4 = $9, updated_at = $10, metadata = $11 WHERE id = $1
		RETURNING id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata`
	qListPayments                   = `SELECT id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata FROM payments WHERE invoice_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	qSetTenantPaymentProviderConfig = `INSERT INTO tenant_payment_provider_config (tenant_id, provider, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (tenant_id)
		DO UPDATE SET provider = EXCLUDED.provider, updated_at = NOW()
		RETURNING tenant_id, provider, updated_at`
	qGetTenantPaymentProviderConfig = `SELECT tenant_id, provider, updated_at FROM tenant_payment_provider_config WHERE tenant_id = $1`
	qSavePayment                    = `INSERT INTO payments (id, amount, currency, status, provider, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW(), metadata = EXCLUDED.metadata`
	qListFailedPayments   = `SELECT id, invoice_id, dunning_attempts, dunning_state, last_dunning_attempt FROM payments WHERE tenant_id = $1 AND status = 'failed' AND dunning_state != 'recovered'`
	qGetDunningConfig     = `SELECT max_attempts, retry_intervals_json FROM tenant_dunning_config WHERE tenant_id = $1`
	qUpdateDunningState   = `UPDATE payments SET dunning_state = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3`
	qUpdateDunningAttempt = `UPDATE payments SET last_dunning_attempt = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3`
	qCreateDispute        = `INSERT INTO disputes (id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	qGetDispute            = `SELECT id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json FROM disputes WHERE id = $1`
	qUpdateDisputeStatus   = `UPDATE disputes SET status = $1, evidence_submitted = $2, updated_at = NOW() WHERE id = $3`
	qCreateDisputeEvidence = `INSERT INTO dispute_evidence (id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	qGetDisputeEvidence          = `SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json FROM dispute_evidence WHERE id = $1`
	qUpdateDisputeEvidenceStatus = `UPDATE dispute_evidence SET provider_status = $1, provider_response = $2, updated_at = NOW() WHERE id = $3`
	qCreateManualRefund          = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata`
	qGetPaymentByIdempotencyKey = `SELECT id, invoice_id, amount, status, method, created_at, updated_at, metadata FROM payments WHERE metadata::jsonb ->> 'idempotency_key' = $1 LIMIT 1`
	qMarkPaymentsPaidForInvoice = `UPDATE payments SET status = 'paid', updated_at = NOW() WHERE invoice_id = $1`
	qUpdateInvoiceStatus        = `UPDATE invoices SET status = $2, updated_at = NOW() WHERE id = $1`
	qUpdatePaymentStatus        = `UPDATE payments SET status = $2, updated_at = NOW() WHERE id = $1`
	qDeleteDispute              = `UPDATE disputes SET status = 'closed', updated_at = NOW() WHERE id = $1`
	qDeleteDisputeEvidence      = `UPDATE dispute_evidence SET provider_status = 'deleted', updated_at = NOW() WHERE id = $1`
	qSetPaymentPluginConfig     = `INSERT INTO payment_plugin_config (tenant_id, plugin_name, updated_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET plugin_name = $2, updated_at = $3
		RETURNING tenant_id, plugin_name, updated_at`
	qListDisputes              = `SELECT id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json FROM disputes WHERE tenant_id = $1`
	qListDisputeEvidence       = `SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json FROM dispute_evidence WHERE dispute_id = $1 AND tenant_id = $2 ORDER BY uploaded_at DESC LIMIT $3 OFFSET $4`
	qListPaymentPluginConfigs  = `SELECT id, tenant_id, plugin_name, config, is_enabled, is_default, created_at, updated_at FROM payment_plugin_configs WHERE tenant_id = $1 ORDER BY plugin_name`
	qDisablePaymentPlugin      = `UPDATE payment_plugin_configs SET is_enabled = false, updated_at = $1 WHERE tenant_id = $2 AND plugin_name = $3`
	qGetDefaultPaymentPlugin   = `SELECT id, tenant_id, plugin_name, config, is_enabled, is_default, created_at, updated_at FROM payment_plugin_configs WHERE tenant_id = $1 AND is_default = true AND is_enabled = true`
	qGetPaymentPluginConfig    = `SELECT id, tenant_id, plugin_name, config, is_enabled, is_default, created_at, updated_at FROM payment_plugin_configs WHERE tenant_id = $1 AND plugin_name = $2`
	qUnsetDefaultPaymentPlugin = `UPDATE payment_plugin_configs SET is_default = false, updated_at = $1 WHERE tenant_id = $2 AND is_default = true`
	qUpsertPaymentPluginConfig = `INSERT INTO payment_plugin_configs (id, tenant_id, plugin_name, config, is_enabled, is_default, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (tenant_id, plugin_name)
	DO UPDATE SET config = $4, is_enabled = $5, is_default = $6, updated_at = $8`
	qDeleteRefund = `DELETE FROM refunds WHERE id = $1`
)

// --- Refund CRUD ---
func (s *PostgresStore) CreateRefund(ctx context.Context, r Refund) (Refund, error) {
	row := s.DB.QueryRow(ctx, qCreateRefund, r.ID, r.PaymentID, r.InvoiceID, r.Amount, r.Currency, r.OriginalAmount, r.OriginalCurrency, r.Reason, r.Status, r.CreatedAt, r.UpdatedAt, r.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateRefund failed", logger.ErrorField(err), logger.Any("refund", r))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetRefund(ctx context.Context, id string) (Refund, error) {
	row := s.DB.QueryRow(ctx, qGetRefund, id)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetRefund: not found", logger.String("id", id))
			return Refund{}, sql.ErrNoRows
		}
		logger.LogError("GetRefund failed", logger.ErrorField(err), logger.String("id", id))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateRefund(ctx context.Context, r Refund) (Refund, error) {
	row := s.DB.QueryRow(ctx, qUpdateRefund, r.ID, r.PaymentID, r.InvoiceID, r.Amount, r.Currency, r.OriginalAmount, r.OriginalCurrency, r.Reason, r.Status, r.UpdatedAt, r.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdateRefund failed", logger.ErrorField(err), logger.Any("refund", r))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]Refund, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := qListRefunds + " AND payment_id = $1 AND invoice_id = $2 AND status = $3 ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args := []interface{}{paymentID, invoiceID, status, pageSize, (page - 1) * pageSize}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListRefunds query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Refund
	for rows.Next() {
		var r Refund
		if err := rows.Scan(&r.ID, &r.PaymentID, &r.InvoiceID, &r.Amount, &r.Currency, &r.OriginalAmount, &r.OriginalCurrency, &r.Reason, &r.Status, &r.CreatedAt, &r.UpdatedAt, &r.Metadata); err != nil {
			logger.LogError("ListRefunds scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
func (s *PostgresStore) DeleteRefund(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, qDeleteRefund, id)
	if err != nil {
		logger.LogError("DeleteRefund failed", logger.ErrorField(err), logger.String("id", id))
		return err
	}
	return nil
}

// --- Payment CRUD ---
func (s *PostgresStore) CreatePayment(ctx context.Context, p Payment) (Payment, error) {
	row := s.DB.QueryRow(ctx, qCreatePayment, p.ID, p.InvoiceID, p.Amount, p.Currency, p.OriginalAmount, p.OriginalCurrency, p.Status, p.Method, p.Last4, p.CreatedAt, p.UpdatedAt, p.Metadata)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Status, &out.Method, &out.Last4, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreatePayment failed", logger.ErrorField(err), logger.Any("payment", p))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPayment(ctx context.Context, id string) (Payment, error) {
	row := s.DB.QueryRow(ctx, qGetPayment, id)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Status, &out.Method, &out.Last4, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			logger.LogWarn("GetPayment: not found", logger.String("id", id))
			return Payment{}, errors.New("no rows")
		}
		logger.LogError("GetPayment failed", logger.ErrorField(err), logger.String("id", id))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdatePayment(ctx context.Context, p Payment) (Payment, error) {
	row := s.DB.QueryRow(ctx, qUpdatePayment, p.ID, p.InvoiceID, p.Amount, p.Currency, p.OriginalAmount, p.OriginalCurrency, p.Status, p.Method, p.Last4, p.UpdatedAt, p.Metadata)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Status, &out.Method, &out.Last4, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdatePayment failed", logger.ErrorField(err), logger.Any("payment", p))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPayments(ctx context.Context, invoiceID string, page, pageSize int) ([]Payment, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = qListPayments
	offset := (page - 1) * pageSize
	rows, err := s.DB.Query(ctx, q, invoiceID, pageSize, offset)
	if err != nil {
		logger.LogError("ListPayments query failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, err
	}
	defer rows.Close()
	var out []Payment
	for rows.Next() {
		var p Payment
		if err := rows.Scan(&p.ID, &p.InvoiceID, &p.Amount, &p.Currency, &p.OriginalAmount, &p.OriginalCurrency, &p.Status, &p.Method, &p.Last4, &p.CreatedAt, &p.UpdatedAt, &p.Metadata); err != nil {
			logger.LogError("ListPayments scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *PostgresStore) SetTenantPaymentProviderConfig(ctx context.Context, tenantID, provider string) (*TenantPaymentProviderConfig, error) {
	if tenantID == "" {
		logger.LogError("SetTenantPaymentProviderConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	if provider == "" {
		logger.LogError("SetTenantPaymentProviderConfig: provider must not be empty", logger.ErrorField(errors.New("provider must not be empty")))
		return nil, errors.New("provider must not be empty")
	}

	var cfg TenantPaymentProviderConfig
	err := s.DB.QueryRow(ctx, qSetTenantPaymentProviderConfig, tenantID, provider).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
	if err != nil {
		logger.LogError("SetTenantPaymentProviderConfig: failed to upsert tenant payment provider config", logger.ErrorField(err))
		return nil, errors.New("failed to upsert tenant payment provider config")
	}
	return &cfg, nil
}

func (s *PostgresStore) GetTenantPaymentProviderConfig(ctx context.Context, tenantID string) (*TenantPaymentProviderConfig, error) {
	if tenantID == "" {
		logger.LogError("GetTenantPaymentProviderConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}

	var cfg TenantPaymentProviderConfig
	err := s.DB.QueryRow(ctx, qGetTenantPaymentProviderConfig, tenantID).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
	if err != nil {
		logger.LogError("GetTenantPaymentProviderConfig: failed to get tenant payment provider config", logger.ErrorField(err))
		return nil, errors.New("failed to get tenant payment provider config")
	}
	return &cfg, nil
}

func (s *PostgresStore) SavePayment(ctx context.Context, p *PaymentResult) error {
	if p == nil {
		logger.LogError("SavePayment: payment must not be nil", logger.ErrorField(errors.New("payment must not be nil")))
		return errors.New("payment must not be nil")
	}
	meta, err := json.Marshal(p.Raw)
	if err != nil {
		logger.LogError("SavePayment: failed to marshal payment raw", logger.ErrorField(err))
		return errors.New("failed to marshal payment raw")
	}
	_, err = s.DB.Exec(ctx, qSavePayment, p.PaymentID, p.Amount, p.Currency, p.Status, p.Provider, p.CreatedAt, string(meta))
	if err != nil {
		logger.LogError("SavePayment: failed to save payment", logger.ErrorField(err))
		return errors.New("failed to save payment")
	}
	return nil
}

func (s *PostgresStore) SetTenantProviderSecret(ctx context.Context, tenantID, provider string, config map[string]string) error {
	if tenantID == "" || provider == "" {
		logger.LogError("SetTenantProviderSecret: tenant_id and provider required", logger.ErrorField(errors.New("tenant_id and provider required")))
		return errors.New("tenant_id and provider required")
	}

	cfgJSON, err := json.Marshal(config)
	if err != nil {
		logger.LogError("SetTenantProviderSecret: failed to marshal config", logger.ErrorField(err))
		return errors.New("failed to marshal config")
	}

	_, err = s.DB.Exec(ctx,
		`INSERT INTO tenant_provider_secret (tenant_id, provider, config_json, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (tenant_id, provider)
		DO UPDATE SET config_json = EXCLUDED.config_json, updated_at = NOW()`,
		tenantID, provider, string(cfgJSON))
	if err != nil {
		logger.LogError("SetTenantProviderSecret: failed to upsert secret", logger.ErrorField(err))
		return errors.New("failed to upsert tenant provider secret")
	}
	return nil
}

func (s *PostgresStore) GetTenantProviderSecret(ctx context.Context, tenantID, provider string) (map[string]string, error) {
	if tenantID == "" || provider == "" {
		logger.LogError("GetTenantProviderSecret: tenant_id and provider required", logger.ErrorField(errors.New("tenant_id and provider required")))
		return nil, errors.New("tenant_id and provider required")
	}

	var cfgJSON string
	err := s.DB.QueryRow(ctx,
		`SELECT config_json FROM tenant_provider_secret WHERE tenant_id = $1 AND provider = $2`,
		tenantID, provider).Scan(&cfgJSON)
	if err != nil {
		logger.LogError("GetTenantProviderSecret: failed to get secret", logger.ErrorField(err))
		return nil, errors.New("failed to get tenant provider secret")
	}
	var config map[string]string
	err = json.Unmarshal([]byte(cfgJSON), &config)
	if err != nil {
		logger.LogError("GetTenantProviderSecret: failed to unmarshal config", logger.ErrorField(err))
		return nil, errors.New("failed to unmarshal config")
	}
	return config, nil
}

// ListFailedPayments returns all failed payments for a tenant that are not recovered
func (s *PostgresStore) ListFailedPayments(ctx context.Context, tenantID string) ([]*FailedPayment, error) {
	if tenantID == "" {
		logger.LogError("ListFailedPayments: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	const q = qListFailedPayments
	rows, err := s.DB.Query(ctx, q, tenantID)
	if err != nil {
		logger.LogError("ListFailedPayments: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to list failed payments")
	}
	defer rows.Close()
	var out []*FailedPayment
	for rows.Next() {
		var p FailedPayment
		err := rows.Scan(&p.ID, &p.InvoiceID, &p.DunningAttempts, &p.DunningState, &p.LastDunningAttempt)
		if err != nil {
			logger.LogError("ListFailedPayments: scan failed", logger.ErrorField(err))
			continue
		}
		out = append(out, &p)
	}
	return out, nil
}

// GetDunningConfig loads dunning config for a tenant
func (s *PostgresStore) GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error) {
	if tenantID == "" {
		logger.LogError("GetDunningConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	const q = qGetDunningConfig
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

// UpdateDunningState sets dunning_state and dunning_attempts for a payment
func (s *PostgresStore) UpdateDunningState(ctx context.Context, paymentID, state string, attempts int) error {
	if paymentID == "" {
		logger.LogError("UpdateDunningState: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return errors.New("payment_id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qUpdateDunningState, state, attempts, paymentID)
	if err != nil {
		logger.LogError("UpdateDunningState: update failed", logger.ErrorField(err))
		return errors.New("failed to update dunning state")
	}
	return nil
}

// UpdateDunningAttempt sets last_dunning_attempt and dunning_attempts for a payment
func (s *PostgresStore) UpdateDunningAttempt(ctx context.Context, paymentID string, lastAttempt time.Time, attempts int) error {
	if paymentID == "" {
		logger.LogError("UpdateDunningAttempt: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return errors.New("payment_id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qUpdateDunningAttempt, lastAttempt, attempts, paymentID)
	if err != nil {
		logger.LogError("UpdateDunningAttempt: update failed", logger.ErrorField(err))
		return errors.New("failed to update dunning attempt")
	}
	return nil
}

// CreateDispute inserts a new dispute record
func (s *PostgresStore) CreateDispute(ctx context.Context, d *Dispute) error {
	if d == nil {
		logger.LogError("CreateDispute: dispute must not be nil", logger.ErrorField(errors.New("dispute must not be nil")))
		return errors.New("dispute must not be nil")
	}
	raw, _ := json.Marshal(d.Raw)
	_, err := s.DB.Exec(ctx, qCreateDispute, d.ID, d.PaymentID, d.TenantID, d.Provider, d.Status, d.Reason, d.Amount, d.Currency, d.EvidenceDue, d.EvidenceSubmitted, d.CreatedAt, d.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("CreateDispute: insert failed", logger.ErrorField(err))
		return errors.New("failed to create dispute")
	}
	return nil
}

// GetDispute fetches a dispute by ID
func (s *PostgresStore) GetDispute(ctx context.Context, disputeID string) (*Dispute, error) {
	if disputeID == "" {
		logger.LogError("GetDispute: dispute_id must not be empty", logger.ErrorField(errors.New("dispute_id must not be empty")))
		return nil, errors.New("dispute_id must not be empty")
	}
	const q = qGetDispute
	var d Dispute
	var raw string
	var status string
	var evidenceDue, evidenceSubmitted *time.Time
	err := s.DB.QueryRow(ctx, q, disputeID).Scan(&d.ID, &d.PaymentID, &d.TenantID, &d.Provider, &status, &d.Reason, &d.Amount, &d.Currency, &evidenceDue, &evidenceSubmitted, &d.CreatedAt, &d.UpdatedAt, &raw)
	if err != nil {
		logger.LogError("GetDispute: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to get dispute")
	}
	d.Status = DisputeStatus(status)
	d.EvidenceDue = evidenceDue
	d.EvidenceSubmitted = evidenceSubmitted
	_ = json.Unmarshal([]byte(raw), &d.Raw)
	return &d, nil
}

// ListDisputes returns disputes for a tenant/payment, optionally filtered by status
func (s *PostgresStore) ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error) {
	if tenantID == "" {
		logger.LogError("ListDisputes: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := qListDisputes
	args := []interface{}{tenantID}
	argIdx := 2
	if paymentID != "" {
		q += ` AND payment_id = $` + strconv.Itoa(argIdx)
		args = append(args, paymentID)
		argIdx++
	}
	if status != "" {
		q += ` AND status = $` + strconv.Itoa(argIdx)
		args = append(args, string(status))
		argIdx++
	}
	q += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListDisputes: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to list disputes")
	}
	defer rows.Close()
	var out []*Dispute
	for rows.Next() {
		var d Dispute
		var raw string
		var status string
		var evidenceDue, evidenceSubmitted *time.Time
		err := rows.Scan(&d.ID, &d.PaymentID, &d.TenantID, &d.Provider, &status, &d.Reason, &d.Amount, &d.Currency, &evidenceDue, &evidenceSubmitted, &d.CreatedAt, &d.UpdatedAt, &raw)
		if err != nil {
			logger.LogError("ListDisputes: scan failed", logger.ErrorField(err))
			continue
		}
		d.Status = DisputeStatus(status)
		d.EvidenceDue = evidenceDue
		d.EvidenceSubmitted = evidenceSubmitted
		_ = json.Unmarshal([]byte(raw), &d.Raw)
		out = append(out, &d)
	}
	return out, nil
}

// UpdateDisputeStatus sets status and evidence_submitted for a dispute
func (s *PostgresStore) UpdateDisputeStatus(ctx context.Context, disputeID string, status DisputeStatus, evidenceSubmitted *time.Time) error {
	if disputeID == "" {
		logger.LogError("UpdateDisputeStatus: dispute_id must not be empty", logger.ErrorField(errors.New("dispute_id must not be empty")))
		return errors.New("dispute_id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qUpdateDisputeStatus, string(status), evidenceSubmitted, disputeID)
	if err != nil {
		logger.LogError("UpdateDisputeStatus: update failed", logger.ErrorField(err))
		return errors.New("failed to update dispute status")
	}
	return nil
}

// CreateDisputeEvidence inserts a new evidence record
func (s *PostgresStore) CreateDisputeEvidence(ctx context.Context, e *DisputeEvidence) error {
	if e == nil {
		logger.LogError("CreateDisputeEvidence: evidence must not be nil", logger.ErrorField(errors.New("evidence must not be nil")))
		return errors.New("evidence must not be nil")
	}
	raw, _ := json.Marshal(e.Raw)
	_, err := s.DB.Exec(ctx, qCreateDisputeEvidence, e.ID, e.DisputeID, e.TenantID, e.FileURL, e.FileName, e.FileType, e.UploadedBy, e.UploadedAt, e.ProviderStatus, e.ProviderResponse, e.CreatedAt, e.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("CreateDisputeEvidence: insert failed", logger.ErrorField(err))
		return errors.New("failed to create dispute evidence")
	}
	return nil
}

// GetDisputeEvidence fetches an evidence record by ID
func (s *PostgresStore) GetDisputeEvidence(ctx context.Context, evidenceID string) (*DisputeEvidence, error) {
	if evidenceID == "" {
		logger.LogError("GetDisputeEvidence: evidence_id must not be empty", logger.ErrorField(errors.New("evidence_id must not be empty")))
		return nil, errors.New("evidence_id must not be empty")
	}
	const q = qGetDisputeEvidence
	var e DisputeEvidence
	var raw string
	err := s.DB.QueryRow(ctx, q, evidenceID).Scan(&e.ID, &e.DisputeID, &e.TenantID, &e.FileURL, &e.FileName, &e.FileType, &e.UploadedBy, &e.UploadedAt, &e.ProviderStatus, &e.ProviderResponse, &e.CreatedAt, &e.UpdatedAt, &raw)
	if err != nil {
		logger.LogError("GetDisputeEvidence: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to get dispute evidence")
	}
	_ = json.Unmarshal([]byte(raw), &e.Raw)
	return &e, nil
}

// ListDisputeEvidence returns evidence for a dispute/tenant
func (s *PostgresStore) GetTransactionReport(ctx context.Context, tenantID string, startDate, endDate time.Time, includeDailyTotals bool) (*TransactionReport, error) {
	if tenantID == "" {
		logger.LogError("GetTransactionReport: tenant ID is required", logger.ErrorField(errors.New("tenant ID is required")))
		return nil, errors.New("tenant ID is required")
	}

	// Initialize report
	report := &TransactionReport{
		StartDate:          startDate,
		EndDate:            endDate,
		PaymentMethodStats: make(map[string]int),
	}

	// Get overall transaction totals (successful payments)
	const paymentQuery = `
		SELECT 
			COALESCE(SUM(amount), 0) as total_amount, 
			COUNT(*) as transaction_count,
			SUM(CASE WHEN status = 'succeeded' OR status = 'paid' THEN 1 ELSE 0 END) as success_count,
			SUM(CASE WHEN status = 'failed' OR status = 'payment_failed' THEN 1 ELSE 0 END) as failed_count,
			MAX(currency) as currency
		FROM payments
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
	`

	err := s.DB.QueryRow(ctx, paymentQuery, tenantID, startDate, endDate).Scan(
		&report.TotalAmount,
		&report.TransactionCount,
		&report.SuccessCount,
		&report.FailedCount,
		&report.Currency,
	)
	if err != nil {
		logger.LogError("GetTransactionReport: payment query failed", logger.ErrorField(err))
		return nil, err
	}

	// Get refund totals
	const refundQuery = `
		SELECT 
			COALESCE(SUM(amount), 0) as refund_amount, 
			COUNT(*) as refund_count
		FROM refunds
		JOIN payments ON refunds.payment_id = payments.id
		WHERE payments.tenant_id = $1 AND refunds.created_at BETWEEN $2 AND $3
	`

	err = s.DB.QueryRow(ctx, refundQuery, tenantID, startDate, endDate).Scan(
		&report.RefundAmount,
		&report.RefundCount,
	)
	if err != nil {
		logger.LogError("GetTransactionReport: refund query failed", logger.ErrorField(err))
		// Continue with report, don't fail because of refund query
	}

	// Get dispute totals
	const disputeQuery = `
		SELECT 
			COALESCE(SUM(amount), 0) as dispute_amount, 
			COUNT(*) as dispute_count
		FROM disputes
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
	`

	err = s.DB.QueryRow(ctx, disputeQuery, tenantID, startDate, endDate).Scan(
		&report.DisputeAmount,
		&report.DisputeCount,
	)
	if err != nil {
		logger.LogError("GetTransactionReport: dispute query failed", logger.ErrorField(err))
		// Continue with report, don't fail because of dispute query
	}

	// Calculate net amount (total - refunds - disputes)
	report.NetAmount = report.TotalAmount - report.RefundAmount - report.DisputeAmount

	// Get payment method distribution
	paymentMethodStats, err := s.GetPaymentMethodReport(ctx, tenantID, startDate, endDate)
	if err != nil {
		logger.LogError("GetTransactionReport: payment method query failed", logger.ErrorField(err))
		// Continue with report
	} else {
		report.PaymentMethodStats = paymentMethodStats
	}

	// Get daily totals if requested
	if includeDailyTotals {
		const dailyQuery = `
			SELECT 
				DATE(created_at) as day,
				COALESCE(SUM(amount), 0) as daily_amount,
				COUNT(*) as daily_count
			FROM payments
			WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
			GROUP BY DATE(created_at)
			ORDER BY day
		`

		rows, err := s.DB.Query(ctx, dailyQuery, tenantID, startDate, endDate)
		if err != nil {
			logger.LogError("GetTransactionReport: daily totals query failed", logger.ErrorField(err))
			// Continue with report
		} else {
			defer rows.Close()

			for rows.Next() {
				var day time.Time
				var dailyTotal DailyTransactionTotal

				if err := rows.Scan(&day, &dailyTotal.Amount, &dailyTotal.Count); err != nil {
					logger.LogError("GetTransactionReport: daily totals scan failed", logger.ErrorField(err))
					continue
				}

				dailyTotal.Date = day

				// For each day, get refund and dispute data
				const dailyRefundQuery = `
					SELECT 
						COALESCE(SUM(r.amount), 0) as refund_amount,
						COUNT(*) as refund_count
					FROM refunds r
					JOIN payments p ON r.payment_id = p.id
					WHERE p.tenant_id = $1 AND DATE(r.created_at) = $2
				`

				err = s.DB.QueryRow(ctx, dailyRefundQuery, tenantID, day).Scan(
					&dailyTotal.RefundAmount,
					&dailyTotal.RefundCount,
				)
				if err != nil {
					logger.LogError("GetTransactionReport: daily refund query failed", logger.ErrorField(err), logger.String("date", day.String()))
					// Continue with daily report
				}

				const dailyDisputeQuery = `
					SELECT 
						COALESCE(SUM(amount), 0) as dispute_amount,
						COUNT(*) as dispute_count
					FROM disputes
					WHERE tenant_id = $1 AND DATE(created_at) = $2
				`

				err = s.DB.QueryRow(ctx, dailyDisputeQuery, tenantID, day).Scan(
					&dailyTotal.DisputeAmount,
					&dailyTotal.DisputeCount,
				)
				if err != nil {
					logger.LogError("GetTransactionReport: daily dispute query failed", logger.ErrorField(err), logger.String("date", day.String()))
					// Continue with daily report
				}

				report.DailyTotals = append(report.DailyTotals, dailyTotal)
			}
		}
	}

	return report, nil
}

func (s *PostgresStore) GetPaymentMethodReport(ctx context.Context, tenantID string, startDate, endDate time.Time) (map[string]int, error) {
	if tenantID == "" {
		logger.LogError("GetPaymentMethodReport: tenant ID is required", logger.ErrorField(errors.New("tenant ID is required")))
		return nil, errors.New("tenant ID is required")
	}

	const query = `
		SELECT 
			method,
			COUNT(*) as count
		FROM payments
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY method
	`

	rows, err := s.DB.Query(ctx, query, tenantID, startDate, endDate)
	if err != nil {
		logger.LogError("GetPaymentMethodReport: query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()

	methodStats := make(map[string]int)
	for rows.Next() {
		var method string
		var count int

		if err := rows.Scan(&method, &count); err != nil {
			logger.LogError("GetPaymentMethodReport: scan failed", logger.ErrorField(err))
			continue
		}

		methodStats[method] = count
	}

	return methodStats, nil
}

func (s *PostgresStore) GetTransactionVolume(ctx context.Context, tenantID string, startDate, endDate time.Time) (float64, int, error) {
	if tenantID == "" {
		logger.LogError("GetTransactionVolume: tenant ID is required", logger.ErrorField(errors.New("tenant ID is required")))
		return 0, 0, errors.New("tenant ID is required")
	}

	const query = `
		SELECT 
			COALESCE(SUM(amount), 0) as total_amount,
			COUNT(*) as transaction_count
		FROM payments
		WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
		AND (status = 'succeeded' OR status = 'paid')
	`

	var totalAmount float64
	var transactionCount int

	err := s.DB.QueryRow(ctx, query, tenantID, startDate, endDate).Scan(&totalAmount, &transactionCount)
	if err != nil {
		logger.LogError("GetTransactionVolume: query failed", logger.ErrorField(err))
		return 0, 0, err
	}

	return totalAmount, transactionCount, nil
}

func (s *PostgresStore) ListDisputeEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error) {
	if disputeID == "" || tenantID == "" {
		logger.LogError("ListDisputeEvidence: dispute_id and tenant_id must not be empty", logger.ErrorField(errors.New("dispute_id and tenant_id must not be empty")))
		return nil, errors.New("dispute_id and tenant_id must not be empty")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	rows, err := s.DB.Query(ctx, qListDisputeEvidence, disputeID, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("ListDisputeEvidence: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to list dispute evidence")
	}
	defer rows.Close()
	var out []*DisputeEvidence
	for rows.Next() {
		var e DisputeEvidence
		var raw string
		err := rows.Scan(&e.ID, &e.DisputeID, &e.TenantID, &e.FileURL, &e.FileName, &e.FileType, &e.UploadedBy, &e.UploadedAt, &e.ProviderStatus, &e.ProviderResponse, &e.CreatedAt, &e.UpdatedAt, &raw)
		if err != nil {
			logger.LogError("ListDisputeEvidence: scan failed", logger.ErrorField(err))
			continue
		}
		_ = json.Unmarshal([]byte(raw), &e.Raw)
		out = append(out, &e)
	}
	return out, nil
}

// UpdateDisputeEvidenceStatus sets provider_status and provider_response for an evidence record
func (s *PostgresStore) UpdateDisputeEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error {
	if evidenceID == "" {
		logger.LogError("UpdateDisputeEvidenceStatus: evidence_id must not be empty", logger.ErrorField(errors.New("evidence_id must not be empty")))
		return errors.New("evidence_id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qUpdateDisputeEvidenceStatus, providerStatus, providerResponse, evidenceID)
	if err != nil {
		logger.LogError("UpdateDisputeEvidenceStatus: update failed", logger.ErrorField(err))
		return errors.New("failed to update dispute evidence status")
	}
	return nil
}

func (s *PostgresStore) CreateManualRefund(ctx context.Context, refund Refund) (Refund, error) {
	row := s.DB.QueryRow(ctx, qCreateManualRefund, refund.ID, refund.PaymentID, refund.InvoiceID, refund.Amount, refund.Currency, refund.Status, refund.Reason, refund.CreatedAt, refund.UpdatedAt, refund.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Status, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateManualRefund failed", logger.ErrorField(err), logger.Any("refund", refund))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPaymentByIdempotencyKey(ctx context.Context, idempotencyKey string) (Payment, error) {
	const q = qGetPaymentByIdempotencyKey
	row := s.DB.QueryRow(ctx, q, idempotencyKey)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Status, &out.Method, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if err.Error() == "no rows in result set" {
			return Payment{}, nil
		}
		logger.LogError("GetPaymentByIdempotencyKey failed", logger.ErrorField(err), logger.String("idempotency_key", idempotencyKey))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPaymentResult(ctx context.Context, id string) (*PaymentResult, error) {
	p, err := s.GetPayment(ctx, id) // existing method
	if err != nil {
		logger.LogError("GetPaymentResult: get payment failed", logger.ErrorField(err))
		return nil, err
	}
	return &PaymentResult{
		PaymentID: p.ID,
		Status:    p.Status,
		Amount:    p.Amount,
		Currency:  p.Currency,
		CreatedAt: p.CreatedAt,
		Provider:  p.Method, // or map to correct provider field if needed
		Raw:       p,
	}, nil
}

func (s *PostgresStore) MarkPaymentsPaidForInvoice(ctx context.Context, invoiceID string) error {
	if invoiceID == "" {
		logger.LogError("MarkPaymentsPaidForInvoice: invoice_id required", logger.ErrorField(errors.New("invoice_id required")))
		return errors.New("invoice_id required")
	}
	_, err := s.DB.Exec(ctx, qMarkPaymentsPaidForInvoice, invoiceID)
	if err != nil {
		logger.LogError("MarkPaymentsPaidForInvoice: update failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return err
	}
	return nil
}

func (s *PostgresStore) UpdateInvoiceStatus(ctx context.Context, invoiceID, status string) error {
	if invoiceID == "" || status == "" {
		logger.LogError("UpdateInvoiceStatus: invoiceID and status required", logger.ErrorField(errors.New("invoiceID and status required")))
		return errors.New("invoiceID and status required")
	}
	_, err := s.DB.Exec(ctx, qUpdateInvoiceStatus, invoiceID, status)
	if err != nil {
		logger.LogError("UpdateInvoiceStatus failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID), logger.String("status", status))
		return err
	}
	return nil
}

func (s *PostgresStore) UpdatePaymentStatus(ctx context.Context, paymentID, status string) error {
	if paymentID == "" || status == "" {
		logger.LogError("UpdatePaymentStatus: paymentID and status required", logger.ErrorField(errors.New("paymentID and status required")))
		return errors.New("paymentID and status required")
	}
	_, err := s.DB.Exec(ctx, qUpdatePaymentStatus, paymentID, status)
	if err != nil {
		logger.LogError("UpdatePaymentStatus failed", logger.ErrorField(err), logger.String("payment_id", paymentID), logger.String("status", status))
		return err
	}
	return nil
}

// DeleteDispute sets status to 'closed' for soft delete
func (s *PostgresStore) DeleteDispute(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("DeleteDispute: id must not be empty", logger.ErrorField(errors.New("id must not be empty")))
		return errors.New("id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qDeleteDispute, id)
	if err != nil {
		logger.LogError("DeleteDispute: update failed", logger.ErrorField(err))
		return errors.New("failed to delete dispute")
	}
	return nil
}

// DeleteDisputeEvidence sets provider_status to 'deleted' for soft delete
func (s *PostgresStore) DeleteDisputeEvidence(ctx context.Context, evidenceID string) error {
	if evidenceID == "" {
		logger.LogError("DeleteDisputeEvidence: evidence_id must not be empty", logger.ErrorField(errors.New("evidence_id must not be empty")))
		return errors.New("evidence_id must not be empty")
	}
	_, err := s.DB.Exec(ctx, qDeleteDisputeEvidence, evidenceID)
	if err != nil {
		logger.LogError("DeleteDisputeEvidence: update failed", logger.ErrorField(err))
		return errors.New("failed to delete dispute evidence")
	}
	return nil
}

// --- PaymentPluginConfig CRUD ---
func (s *PostgresStore) SetPaymentPluginConfig(ctx context.Context, tenantID, pluginName string) (PaymentPluginConfig, error) {
	if tenantID == "" {
		logger.LogError("SetPaymentPluginConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return PaymentPluginConfig{}, NewValidationError("tenant_id", "must not be empty")
	}
	if pluginName == "" {
		logger.LogError("SetPaymentPluginConfig: plugin_name must not be empty", logger.ErrorField(errors.New("plugin_name must not be empty")))
		return PaymentPluginConfig{}, NewValidationError("plugin_name", "must not be empty")
	}
	updatedAt := time.Now().UTC()
	var cfg PaymentPluginConfig
	err := s.DB.QueryRow(ctx, qSetPaymentPluginConfig, tenantID, pluginName, updatedAt).Scan(&cfg.TenantID, &cfg.PluginName, &cfg.UpdatedAt)
	if err != nil {
		logger.LogError("SetPaymentPluginConfig failed", logger.ErrorField(err), logger.String("tenant_id", tenantID), logger.String("plugin_name", pluginName))
		return PaymentPluginConfig{}, err
	}
	return cfg, nil
}

func (s *PostgresStore) GetPaymentPluginConfig(ctx context.Context, tenantID, pluginName string) (*PaymentPluginConfig, error) {
	if tenantID == "" || pluginName == "" {
		logger.LogError("GetPaymentPluginConfig: tenant_id and plugin_name are required", logger.ErrorField(errors.New("tenant_id and plugin_name are required")))
		return nil, errors.New("tenant_id and plugin_name are required")
	}

	var config PaymentPluginConfig
	var configJSON []byte

	err := s.DB.QueryRow(ctx, qGetPaymentPluginConfig, tenantID, pluginName).Scan(
		&config.ID, &config.TenantID, &config.PluginName, &configJSON, &config.Enabled, &config.Default, &config.CreatedAt, &config.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			logger.LogError("GetPaymentPluginConfig: payment plugin config not found", logger.ErrorField(err))
			return nil, errors.New("payment plugin config not found")
		}
		logger.LogError("GetPaymentPluginConfig: failed to get payment plugin config", logger.ErrorField(err))
		return nil, fmt.Errorf("failed to get payment plugin config: %w", err)
	}

	// Unmarshal the JSON configuration
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config.Config); err != nil {
			logger.LogError("GetPaymentPluginConfig: failed to unmarshal config", logger.ErrorField(err))
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	} else {
		config.Config = make(map[string]interface{})
	}

	return &config, nil
}

// SavePaymentPluginConfig saves a payment plugin configuration
func (s *PostgresStore) SavePaymentPluginConfig(ctx context.Context, config *PaymentPluginConfig) error {
	if config == nil {
		logger.LogError("SavePaymentPluginConfig: config is nil", logger.ErrorField(errors.New("config is nil")))
		return errors.New("config is nil")
	}

	if config.TenantID == "" || config.PluginName == "" {
		logger.LogError("SavePaymentPluginConfig: tenant_id and plugin_name are required", logger.ErrorField(errors.New("tenant_id and plugin_name are required")))
		return errors.New("tenant_id and plugin_name are required")
	}

	// Generate an ID if not provided
	if config.ID == "" {
		config.ID = uuid.NewString()
	}

	// Set timestamps
	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}
	config.UpdatedAt = now

	// Convert config map to JSON
	configJSON, err := json.Marshal(config.Config)
	if err != nil {
		logger.LogError("SavePaymentPluginConfig: failed to marshal config", logger.ErrorField(err))
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// If this is the default plugin, unset any existing default
	if config.Default {
		_, err := s.DB.Exec(ctx, qUnsetDefaultPaymentPlugin, now, config.TenantID)
		if err != nil {
			logger.LogError("SavePaymentPluginConfig: failed to unset existing default plugin", logger.ErrorField(err))
			return fmt.Errorf("failed to unset existing default plugin: %w", err)
		}
	}

	// Upsert the configuration
	_, err = s.DB.Exec(ctx, qUpsertPaymentPluginConfig,
		config.ID, config.TenantID, config.PluginName, configJSON, config.Enabled, config.Default, config.CreatedAt, config.UpdatedAt)

	if err != nil {
		logger.LogError("SavePaymentPluginConfig: failed to save payment plugin config", logger.ErrorField(err))
		return fmt.Errorf("failed to save payment plugin config: %w", err)
	}

	return nil
}

// ListPaymentPluginConfigs lists all payment plugin configurations for a tenant
func (s *PostgresStore) ListPaymentPluginConfigs(ctx context.Context, tenantID string) ([]*PaymentPluginConfig, error) {
	if tenantID == "" {
		logger.LogError("ListPaymentPluginConfigs: tenant_id is required", logger.ErrorField(errors.New("tenant_id is required")))
		return nil, errors.New("tenant_id is required")
	}
	rows, err := s.DB.Query(ctx, qListPaymentPluginConfigs, tenantID)
	if err != nil {
		logger.LogError("ListPaymentPluginConfigs: failed to list payment plugin configs", logger.ErrorField(err))
		return nil, fmt.Errorf("failed to list payment plugin configs: %w", err)
	}
	defer rows.Close()
	var configs []*PaymentPluginConfig
	for rows.Next() {
		var config PaymentPluginConfig
		var configJSON []byte
		err := rows.Scan(
			&config.ID, &config.TenantID, &config.PluginName, &configJSON, &config.Enabled, &config.Default, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			logger.LogError("ListPaymentPluginConfigs: failed to scan payment plugin config", logger.ErrorField(err))
			return nil, fmt.Errorf("failed to scan payment plugin config: %w", err)
		}
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &config.Config); err != nil {
				logger.LogError("ListPaymentPluginConfigs: failed to unmarshal config", logger.ErrorField(err))
				return nil, fmt.Errorf("failed to unmarshal config: %w", err)
			}
		} else {
			config.Config = make(map[string]interface{})
		}
		configs = append(configs, &config)
	}
	if err := rows.Err(); err != nil {
		logger.LogError("ListPaymentPluginConfigs: error iterating payment plugin configs", logger.ErrorField(err))
		return nil, fmt.Errorf("error iterating payment plugin configs: %w", err)
	}
	return configs, nil
}

// DisablePaymentPlugin disables a payment plugin for a tenant
func (s *PostgresStore) DisablePaymentPlugin(ctx context.Context, tenantID, pluginName string) error {
	if tenantID == "" || pluginName == "" {
		logger.LogError("DisablePaymentPlugin: tenant_id and plugin_name are required", logger.ErrorField(errors.New("tenant_id and plugin_name are required")))
		return errors.New("tenant_id and plugin_name are required")
	}
	result, err := s.DB.Exec(ctx, qDisablePaymentPlugin, time.Now(), tenantID, pluginName)
	if err != nil {
		logger.LogError("DisablePaymentPlugin: failed to disable payment plugin", logger.ErrorField(err))
		return fmt.Errorf("failed to disable payment plugin: %w", err)
	}
	if result.RowsAffected() == 0 {
		logger.LogError("DisablePaymentPlugin: payment plugin config not found", logger.ErrorField(errors.New("payment plugin config not found")))
		return errors.New("payment plugin config not found")
	}
	return nil
}

// GetDefaultPaymentPlugin retrieves the default payment plugin for a tenant
func (s *PostgresStore) GetDefaultPaymentPlugin(ctx context.Context, tenantID string) (*PaymentPluginConfig, error) {
	if tenantID == "" {
		logger.LogError("GetDefaultPaymentPlugin: tenant_id is required", logger.ErrorField(errors.New("tenant_id is required")))
		return nil, errors.New("tenant_id is required")
	}
	var config PaymentPluginConfig
	var configJSON []byte
	err := s.DB.QueryRow(ctx, qGetDefaultPaymentPlugin, tenantID).Scan(
		&config.ID, &config.TenantID, &config.PluginName, &configJSON, &config.Enabled, &config.Default, &config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.LogError("GetDefaultPaymentPlugin: default payment plugin not found", logger.ErrorField(err))
			return nil, errors.New("default payment plugin not found")
		}
		logger.LogError("GetDefaultPaymentPlugin: failed to get default payment plugin", logger.ErrorField(err))
		return nil, fmt.Errorf("failed to get default payment plugin: %w", err)
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config.Config); err != nil {
			logger.LogError("GetDefaultPaymentPlugin: failed to unmarshal config", logger.ErrorField(err))
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	} else {
		config.Config = make(map[string]interface{})
	}
	return &config, nil
}

// --- PaymentMethod CRUD ---
func (s *PostgresStore) CreatePaymentMethod(ctx context.Context, input PaymentMethod, data map[string]string) (PaymentMethod, error) {
	if err := input.Validate(); err != nil {
		logger.LogError("CreatePaymentMethod: validation failed", logger.ErrorField(err))
		return PaymentMethod{}, err
	}
	if input.ID == "" {
		input.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	input.CreatedAt = now
	input.UpdatedAt = now
	meta, err := json.Marshal(data)
	if err != nil {
		logger.LogError("CreatePaymentMethod: failed to marshal metadata", logger.ErrorField(err))
		return PaymentMethod{}, errors.New("failed to marshal metadata")
	}
	input.Metadata = string(meta)
	const q = `INSERT INTO payment_methods (id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, token, token_provider, created_at, updated_at, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, token, token_provider, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, input.ID, input.AccountID, input.Type, input.Provider, input.Last4, input.ExpMonth, input.ExpYear, input.IsDefault, input.Status, input.Token, input.TokenProvider, input.CreatedAt, input.UpdatedAt, input.Metadata)
	var out PaymentMethod
	if err := row.Scan(&out.ID, &out.AccountID, &out.Type, &out.Provider, &out.Last4, &out.ExpMonth, &out.ExpYear, &out.IsDefault, &out.Status, &out.Token, &out.TokenProvider, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreatePaymentMethod: insert failed", logger.ErrorField(err))
		return PaymentMethod{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdatePaymentMethod(ctx context.Context, input PaymentMethod) (PaymentMethod, error) {
	if err := input.Validate(); err != nil {
		logger.LogError("UpdatePaymentMethod: validation failed", logger.ErrorField(err))
		return PaymentMethod{}, err
	}
	input.UpdatedAt = time.Now().UTC()
	const q = `UPDATE payment_methods SET account_id=$2, type=$3, provider=$4, last4=$5, exp_month=$6, exp_year=$7, is_default=$8, status=$9, token=$10, token_provider=$11, updated_at=$12, metadata=$13 WHERE id=$1
		RETURNING id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, token, token_provider, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, input.ID, input.AccountID, input.Type, input.Provider, input.Last4, input.ExpMonth, input.ExpYear, input.IsDefault, input.Status, input.Token, input.TokenProvider, input.UpdatedAt, input.Metadata)
	var out PaymentMethod
	if err := row.Scan(&out.ID, &out.AccountID, &out.Type, &out.Provider, &out.Last4, &out.ExpMonth, &out.ExpYear, &out.IsDefault, &out.Status, &out.Token, &out.TokenProvider, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdatePaymentMethod: update failed", logger.ErrorField(err))
		return PaymentMethod{}, err
	}
	return out, nil
}

func (s *PostgresStore) PatchPaymentMethod(ctx context.Context, id string, setDefault *bool, status string) error {
	if id == "" {
		logger.LogError("PatchPaymentMethod: id is required", logger.ErrorField(errors.New("id is required")))
		return errors.New("id is required")
	}
	updates := []string{}
	args := []interface{}{}
	argIdx := 1
	if setDefault != nil {
		updates = append(updates, "is_default = $"+strconv.Itoa(argIdx))
		args = append(args, *setDefault)
		argIdx++
	}
	if status != "" {
		updates = append(updates, "status = $"+strconv.Itoa(argIdx))
		args = append(args, status)
		argIdx++
	}
	if len(updates) == 0 {
		logger.LogError("PatchPaymentMethod: no fields to patch", logger.ErrorField(errors.New("no fields to patch")))
		return errors.New("no fields to patch")
	}
	updates = append(updates, "updated_at = $"+strconv.Itoa(argIdx))
	args = append(args, time.Now().UTC())
	argIdx++
	q := "UPDATE payment_methods SET " + strings.Join(updates, ", ") + " WHERE id = $" + strconv.Itoa(argIdx)
	args = append(args, id)
	res, err := s.DB.Exec(ctx, q, args...)
	if err != nil {
		logger.LogError("PatchPaymentMethod: update failed", logger.ErrorField(err))
		return err
	}
	if res.RowsAffected() == 0 {
		logger.LogError("PatchPaymentMethod: no rows affected", logger.ErrorField(sql.ErrNoRows))
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) DeletePaymentMethod(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("DeletePaymentMethod: id is required", logger.ErrorField(errors.New("id is required")))
		return errors.New("id is required")
	}
	const q = `UPDATE payment_methods SET status='deleted', updated_at=NOW() WHERE id=$1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeletePaymentMethod: update failed", logger.ErrorField(err))
		return err
	}
	if res.RowsAffected() == 0 {
		logger.LogError("DeletePaymentMethod: no rows affected", logger.ErrorField(sql.ErrNoRows))
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) GetPaymentMethod(ctx context.Context, id string) (PaymentMethod, error) {
	if id == "" {
		logger.LogError("GetPaymentMethod: id is required", logger.ErrorField(errors.New("id is required")))
		return PaymentMethod{}, errors.New("id is required")
	}
	const q = `SELECT id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, token, token_provider, created_at, updated_at, metadata FROM payment_methods WHERE id=$1 AND status != 'deleted'`
	row := s.DB.QueryRow(ctx, q, id)
	var out PaymentMethod
	if err := row.Scan(&out.ID, &out.AccountID, &out.Type, &out.Provider, &out.Last4, &out.ExpMonth, &out.ExpYear, &out.IsDefault, &out.Status, &out.Token, &out.TokenProvider, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if err == sql.ErrNoRows {
			logger.LogError("GetPaymentMethod: no rows found", logger.ErrorField(err))
			return PaymentMethod{}, sql.ErrNoRows
		}
		logger.LogError("GetPaymentMethod: query failed", logger.ErrorField(err))
		return PaymentMethod{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]PaymentMethod, error) {
	if accountID == "" {
		logger.LogError("ListPaymentMethods: account_id is required", logger.ErrorField(errors.New("account_id is required")))
		return nil, errors.New("account_id is required")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, type, provider, last4, exp_month, exp_year, is_default, status, token, token_provider, created_at, updated_at, metadata FROM payment_methods WHERE account_id=$1 AND status != 'deleted'`
	args := []interface{}{accountID}
	if status != "" {
		q += " AND status=$2"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListPaymentMethods: query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []PaymentMethod
	for rows.Next() {
		var m PaymentMethod
		if err := rows.Scan(&m.ID, &m.AccountID, &m.Type, &m.Provider, &m.Last4, &m.ExpMonth, &m.ExpYear, &m.IsDefault, &m.Status, &m.Token, &m.TokenProvider, &m.CreatedAt, &m.UpdatedAt, &m.Metadata); err != nil {
			logger.LogError("ListPaymentMethods: scan failed", logger.ErrorField(err))
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *PostgresStore) RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error) {
	if req == nil {
		logger.LogError("RefundPayment: refund request is nil", logger.ErrorField(errors.New("refund request is nil")))
		return nil, errors.New("refund request is nil")
	}
	p, err := s.GetPayment(ctx, req.PaymentID)
	if err != nil {
		logger.LogError("RefundPayment: get payment failed", logger.ErrorField(err))
		return nil, err
	}
	if p.Status == "refunded" {
		logger.LogError("RefundPayment: payment already refunded", logger.ErrorField(errors.New("payment already refunded")))
		return nil, errors.New("payment already refunded")
	}
	refund := Refund{
		ID:        uuid.NewString(),
		PaymentID: req.PaymentID,
		Amount:    req.Amount,
		Currency:  req.Currency,
		Reason:    req.Reason,
		Status:    "processed",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Metadata:  "{}",
	}
	_, err = s.CreateRefund(ctx, refund)
	if err != nil {
		logger.LogError("RefundPayment: create refund failed", logger.ErrorField(err))
		return nil, err
	}
	err = s.UpdatePaymentStatus(ctx, req.PaymentID, "refunded")
	if err != nil {
		logger.LogError("RefundPayment: update payment status failed", logger.ErrorField(err))
		return nil, err
	}
	result := &PaymentResult{
		PaymentID: p.ID,
		Status:    "refunded",
		Amount:    req.Amount,
		Currency:  req.Currency,
		CreatedAt: time.Now().UTC(),
		Provider:  p.Method,
		Raw:       refund,
	}
	return result, nil
}

func (s *PostgresStore) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	if paymentID == "" {
		logger.LogError("GetPaymentStatus: paymentID is required", logger.ErrorField(errors.New("paymentID is required")))
		return nil, errors.New("paymentID is required")
	}
	p, err := s.GetPayment(ctx, paymentID)
	if err != nil {
		logger.LogError("GetPaymentStatus: get payment failed", logger.ErrorField(err))
		return nil, err
	}
	status := &PaymentStatus{
		PaymentID: p.ID,
		Status:    p.Status,
		Amount:    p.Amount,
		Currency:  p.Currency,
		UpdatedAt: p.UpdatedAt,
		Provider:  p.Method,
		Raw:       p,
	}
	return status, nil
}

func (s *PostgresStore) CreateEvidence(ctx context.Context, input *DisputeEvidence) error {
	if input == nil {
		logger.LogError("CreateEvidence: evidence input is nil", logger.ErrorField(errors.New("evidence input is nil")))
		return errors.New("evidence input is nil")
	}
	raw, err := json.Marshal(input.Raw)
	if err != nil {
		logger.LogError("CreateEvidence: marshal raw evidence failed", logger.ErrorField(err))
		return errors.New("failed to marshal raw evidence")
	}
	const q = `INSERT INTO dispute_evidence (id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
	_, err = s.DB.Exec(ctx, q, input.ID, input.DisputeID, input.TenantID, input.FileURL, input.FileName, input.FileType, input.UploadedBy, input.UploadedAt, input.ProviderStatus, input.ProviderResponse, input.CreatedAt, input.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("CreateEvidence: insert failed", logger.ErrorField(err))
		return err
	}
	return nil
}

func (s *PostgresStore) UpdateEvidence(ctx context.Context, input *DisputeEvidence) error {
	if input == nil {
		logger.LogError("UpdateEvidence: evidence input is nil", logger.ErrorField(errors.New("evidence input is nil")))
		return errors.New("evidence input is nil")
	}
	raw, err := json.Marshal(input.Raw)
	if err != nil {
		logger.LogError("UpdateEvidence: marshal raw evidence failed", logger.ErrorField(err))
		return errors.New("failed to marshal raw evidence")
	}
	const q = `UPDATE dispute_evidence SET file_url=$2, file_name=$3, file_type=$4, provider_status=$5, provider_response=$6, updated_at=$7, raw_json=$8 WHERE id=$1`
	_, err = s.DB.Exec(ctx, q, input.ID, input.FileURL, input.FileName, input.FileType, input.ProviderStatus, input.ProviderResponse, input.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("UpdateEvidence: update failed", logger.ErrorField(err))
		return err
	}
	return nil
}

func (s *PostgresStore) DeleteEvidence(ctx context.Context, id string) error {
	if id == "" {
		logger.LogError("DeleteEvidence: evidence id is required", logger.ErrorField(errors.New("evidence id is required")))
		return errors.New("evidence id is required")
	}
	const q = `UPDATE dispute_evidence SET provider_status='deleted', updated_at=NOW() WHERE id=$1`
	res, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteEvidence: update failed", logger.ErrorField(err))
		return err
	}
	if res.RowsAffected() == 0 {
		logger.LogError("DeleteEvidence: no rows affected", logger.ErrorField(sql.ErrNoRows))
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) GetEvidence(ctx context.Context, id string) (*DisputeEvidence, error) {
	if id == "" {
		logger.LogError("GetEvidence: evidence id is required", logger.ErrorField(errors.New("evidence id is required")))
		return nil, errors.New("evidence id is required")
	}
	const q = `SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json FROM dispute_evidence WHERE id=$1 AND provider_status != 'deleted'`
	row := s.DB.QueryRow(ctx, q, id)
	var e DisputeEvidence
	var raw string
	if err := row.Scan(&e.ID, &e.DisputeID, &e.TenantID, &e.FileURL, &e.FileName, &e.FileType, &e.UploadedBy, &e.UploadedAt, &e.ProviderStatus, &e.ProviderResponse, &e.CreatedAt, &e.UpdatedAt, &raw); err != nil {
		if err == sql.ErrNoRows {
			logger.LogError("GetEvidence: no rows found", logger.ErrorField(err), logger.String("id", id))
			return nil, sql.ErrNoRows
		}
		logger.LogError("GetEvidence: query failed", logger.ErrorField(err))
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &e.Raw)
	return &e, nil
}

func (s *PostgresStore) ListEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error) {
	if disputeID == "" || tenantID == "" {
		logger.LogError("ListEvidence: dispute_id and tenant_id are required", logger.ErrorField(errors.New("dispute_id and tenant_id are required")))
		return nil, errors.New("dispute_id and tenant_id are required")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json FROM dispute_evidence WHERE dispute_id=$1 AND tenant_id=$2 AND provider_status != 'deleted' ORDER BY uploaded_at DESC LIMIT $3 OFFSET $4`
	rows, err := s.DB.Query(ctx, q, disputeID, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		logger.LogError("ListEvidence: query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []*DisputeEvidence
	for rows.Next() {
		var e DisputeEvidence
		var raw string
		if err := rows.Scan(&e.ID, &e.DisputeID, &e.TenantID, &e.FileURL, &e.FileName, &e.FileType, &e.UploadedBy, &e.UploadedAt, &e.ProviderStatus, &e.ProviderResponse, &e.CreatedAt, &e.UpdatedAt, &raw); err != nil {
			logger.LogError("ListEvidence: scan failed", logger.ErrorField(err))
			continue
		}
		_ = json.Unmarshal([]byte(raw), &e.Raw)
		out = append(out, &e)
	}
	return out, nil
}

func (s *PostgresStore) UpdateDispute(ctx context.Context, input Dispute) (Dispute, error) {
	if input.ID == "" {
		logger.LogError("UpdateDispute: dispute id is required", logger.ErrorField(errors.New("dispute id is required")))
		return Dispute{}, errors.New("dispute id is required")
	}
	const q = `UPDATE disputes SET status=$2, reason=$3, amount=$4, currency=$5, updated_at=$6 WHERE id=$1
		RETURNING id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json`
	row := s.DB.QueryRow(ctx, q, input.ID, input.Status, input.Reason, input.Amount, input.Currency, time.Now().UTC())
	var out Dispute
	var raw string
	var status string
	var evidenceDue, evidenceSubmitted *time.Time
	err := row.Scan(&out.ID, &out.PaymentID, &out.TenantID, &out.Provider, &status, &out.Reason, &out.Amount, &out.Currency, &evidenceDue, &evidenceSubmitted, &out.CreatedAt, &out.UpdatedAt, &raw)
	if err != nil {
		logger.LogError("UpdateDispute: scan failed", logger.ErrorField(err))
		return Dispute{}, err
	}
	out.Status = DisputeStatus(status)
	out.EvidenceDue = evidenceDue
	out.EvidenceSubmitted = evidenceSubmitted
	err = json.Unmarshal([]byte(raw), &out.Raw)
	if err != nil {
		logger.LogError("UpdateDispute: unmarshal raw failed", logger.ErrorField(err))
		return Dispute{}, err
	}
	return out, nil
}
