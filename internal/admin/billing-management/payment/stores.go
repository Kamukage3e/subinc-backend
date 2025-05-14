package payment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// --- Refund CRUD ---
func (s *PostgresStore) CreateRefund(ctx context.Context, r Refund) (Refund, error) {
	const q = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, r.ID, r.PaymentID, r.InvoiceID, r.Amount, r.Currency, r.OriginalAmount, r.OriginalCurrency, r.Reason, r.Status, r.CreatedAt, r.UpdatedAt, r.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Reason, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateRefund failed", logger.ErrorField(err), logger.Any("refund", r))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetRefund(ctx context.Context, id string) (Refund, error) {
	const q = `SELECT id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata FROM refunds WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
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
	const q = `UPDATE refunds SET payment_id = $2, invoice_id = $3, amount = $4, currency = $5, original_amount = $6, original_currency = $7, reason = $8, status = $9, updated_at = $10, metadata = $11 WHERE id = $1
		RETURNING id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, r.ID, r.PaymentID, r.InvoiceID, r.Amount, r.Currency, r.OriginalAmount, r.OriginalCurrency, r.Reason, r.Status, r.UpdatedAt, r.Metadata)
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
	q := `SELECT id, payment_id, invoice_id, amount, currency, original_amount, original_currency, reason, status, created_at, updated_at, metadata FROM refunds WHERE 1=1`
	args := []interface{}{}
	if paymentID != "" {
		q += " AND payment_id = $1"
		args = append(args, paymentID)
	}
	if invoiceID != "" {
		q += " AND invoice_id = $2"
		args = append(args, invoiceID)
	}
	if status != "" {
		q += " AND status = $3"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args = append(args, pageSize, (page-1)*pageSize)
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

// --- Payment CRUD ---
func (s *PostgresStore) CreatePayment(ctx context.Context, p Payment) (Payment, error) {
	const q = `INSERT INTO payments (id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, p.ID, p.InvoiceID, p.Amount, p.Currency, p.OriginalAmount, p.OriginalCurrency, p.Status, p.Method, p.Last4, p.CreatedAt, p.UpdatedAt, p.Metadata)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Status, &out.Method, &out.Last4, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreatePayment failed", logger.ErrorField(err), logger.Any("payment", p))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPayment(ctx context.Context, id string) (Payment, error) {
	const q = `SELECT id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata FROM payments WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
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
	const q = `UPDATE payments SET invoice_id = $2, amount = $3, currency = $4, original_amount = $5, original_currency = $6, status = $7, method = $8, last4 = $9, updated_at = $10, metadata = $11 WHERE id = $1
		RETURNING id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, p.ID, p.InvoiceID, p.Amount, p.Currency, p.OriginalAmount, p.OriginalCurrency, p.Status, p.Method, p.Last4, p.UpdatedAt, p.Metadata)
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
	const q = `SELECT id, invoice_id, amount, currency, original_amount, original_currency, status, method, last4, created_at, updated_at, metadata FROM payments WHERE invoice_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
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

	const q = `
	INSERT INTO tenant_payment_provider_config (tenant_id, provider, updated_at)
	VALUES ($1, $2, NOW())
	ON CONFLICT (tenant_id)
	DO UPDATE SET provider = EXCLUDED.provider, updated_at = NOW()
	RETURNING tenant_id, provider, updated_at
	`
	var cfg TenantPaymentProviderConfig
	err := s.DB.QueryRow(ctx, q, tenantID, provider).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
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

	const q = `
	SELECT tenant_id, provider, updated_at
	FROM tenant_payment_provider_config
	WHERE tenant_id = $1
	`
	var cfg TenantPaymentProviderConfig
	err := s.DB.QueryRow(ctx, q, tenantID).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
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
	const q = `
	INSERT INTO payments (id, amount, currency, status, provider, created_at, metadata)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = NOW(), metadata = EXCLUDED.metadata
	`
	meta, _ := json.Marshal(p.Raw)
	_, err := s.DB.Exec(ctx, q, p.PaymentID, p.Amount, p.Currency, p.Status, p.Provider, p.CreatedAt, string(meta))
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

	const q = `
	INSERT INTO tenant_provider_secret (tenant_id, provider, config_json, updated_at)
	VALUES ($1, $2, $3, NOW())
	ON CONFLICT (tenant_id, provider)
	DO UPDATE SET config_json = EXCLUDED.config_json, updated_at = NOW()
	`
	_, err = s.DB.Exec(ctx, q, tenantID, provider, string(cfgJSON))
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

	const q = `
	SELECT config_json FROM tenant_provider_secret WHERE tenant_id = $1 AND provider = $2
	`
	var cfgJSON string
	err := s.DB.QueryRow(ctx, q, tenantID, provider).Scan(&cfgJSON)
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
	const q = `
	SELECT id, invoice_id, dunning_attempts, dunning_state, last_dunning_attempt
	FROM payments
	WHERE tenant_id = $1 AND status = 'failed' AND dunning_state != 'recovered'
	`
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

// UpdateDunningState sets dunning_state and dunning_attempts for a payment
func (s *PostgresStore) UpdateDunningState(ctx context.Context, paymentID, state string, attempts int) error {
	if paymentID == "" {
		logger.LogError("UpdateDunningState: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return errors.New("payment_id must not be empty")
	}
	const q = `
	UPDATE payments SET dunning_state = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3
	`
	_, err := s.DB.Exec(ctx, q, state, attempts, paymentID)
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
	const q = `
	UPDATE payments SET last_dunning_attempt = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3
	`
	_, err := s.DB.Exec(ctx, q, lastAttempt, attempts, paymentID)
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
	const q = `
	INSERT INTO disputes (id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`
	_, err := s.DB.Exec(ctx, q, d.ID, d.PaymentID, d.TenantID, d.Provider, d.Status, d.Reason, d.Amount, d.Currency, d.EvidenceDue, d.EvidenceSubmitted, d.CreatedAt, d.UpdatedAt, string(raw))
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
	const q = `
	SELECT id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json
	FROM disputes WHERE id = $1
	`
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
	q := `SELECT id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json FROM disputes WHERE tenant_id = $1`
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
	const q = `UPDATE disputes SET status = $1, evidence_submitted = $2, updated_at = NOW() WHERE id = $3`
	_, err := s.DB.Exec(ctx, q, string(status), evidenceSubmitted, disputeID)
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
	const q = `
	INSERT INTO dispute_evidence (id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`
	_, err := s.DB.Exec(ctx, q, e.ID, e.DisputeID, e.TenantID, e.FileURL, e.FileName, e.FileType, e.UploadedBy, e.UploadedAt, e.ProviderStatus, e.ProviderResponse, e.CreatedAt, e.UpdatedAt, string(raw))
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
	const q = `
	SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json
	FROM dispute_evidence WHERE id = $1
	`
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
	const q = `SELECT id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json FROM dispute_evidence WHERE dispute_id = $1 AND tenant_id = $2 ORDER BY uploaded_at DESC LIMIT $3 OFFSET $4`
	rows, err := s.DB.Query(ctx, q, disputeID, tenantID, pageSize, (page-1)*pageSize)
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
	const q = `UPDATE dispute_evidence SET provider_status = $1, provider_response = $2, updated_at = NOW() WHERE id = $3`
	_, err := s.DB.Exec(ctx, q, providerStatus, providerResponse, evidenceID)
	if err != nil {
		logger.LogError("UpdateDisputeEvidenceStatus: update failed", logger.ErrorField(err))
		return errors.New("failed to update dispute evidence status")
	}
	return nil
}

func (s *PostgresStore) CreateManualRefund(ctx context.Context, refund Refund) (Refund, error) {
	const q = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, refund.ID, refund.PaymentID, refund.InvoiceID, refund.Amount, refund.Currency, refund.Status, refund.Reason, refund.CreatedAt, refund.UpdatedAt, refund.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Status, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateManualRefund failed", logger.ErrorField(err), logger.Any("refund", refund))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPaymentByIdempotencyKey(ctx context.Context, idempotencyKey string) (Payment, error) {
	const q = `SELECT id, invoice_id, amount, status, method, created_at, updated_at, metadata FROM payments WHERE metadata::jsonb ->> 'idempotency_key' = $1 LIMIT 1`
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
	const q = `UPDATE payments SET status = 'paid', updated_at = NOW() WHERE invoice_id = $1`
	_, err := s.DB.Exec(ctx, q, invoiceID)
	if err != nil {
		logger.LogError("MarkPaymentsPaidForInvoice: update failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return err
	}
	return nil
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

func (s *PostgresStore) UpdatePaymentStatus(ctx context.Context, paymentID, status string) error {
	if paymentID == "" || status == "" {
		return errors.New("paymentID and status required")
	}
	const q = `UPDATE payments SET status = $2, updated_at = NOW() WHERE id = $1`
	res, err := s.DB.Exec(ctx, q, paymentID, status)
	if err != nil {
		logger.LogError("UpdatePaymentStatus failed", logger.ErrorField(err), logger.String("payment_id", paymentID), logger.String("status", status))
		return err
	}
	if res.RowsAffected() == 0 {
		return errors.New("payment not found")
	}
	return nil
}
