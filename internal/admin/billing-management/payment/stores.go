package payment

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) SetTenantPaymentProviderConfig(ctx context.Context, tenantID, provider string) (*TenantPaymentProviderConfig, error) {
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
	err := s.pool.QueryRow(ctx, q, tenantID, provider).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
	if err != nil {
		logger.LogError("SetTenantPaymentProviderConfig: failed to upsert tenant payment provider config", logger.ErrorField(err))
		return nil, errors.New("failed to upsert tenant payment provider config")
	}
	return &cfg, nil
}

func (s *Store) GetTenantPaymentProviderConfig(ctx context.Context, tenantID string) (*TenantPaymentProviderConfig, error) {
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
	err := s.pool.QueryRow(ctx, q, tenantID).Scan(&cfg.TenantID, &cfg.Provider, &cfg.UpdatedAt)
	if err != nil {
		logger.LogError("GetTenantPaymentProviderConfig: failed to get tenant payment provider config", logger.ErrorField(err))
		return nil, errors.New("failed to get tenant payment provider config")
	}
	return &cfg, nil
}

func (s *Store) SavePayment(ctx context.Context, p *PaymentResult) error {
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
	_, err := s.pool.Exec(ctx, q, p.PaymentID, p.Amount, p.Currency, p.Status, p.Provider, p.CreatedAt, string(meta))
	if err != nil {
		logger.LogError("SavePayment: failed to save payment", logger.ErrorField(err))
		return errors.New("failed to save payment")
	}
	return nil
}

func (s *Store) GetPayment(ctx context.Context, paymentID string) (*PaymentResult, error) {
	if paymentID == "" {
		logger.LogError("GetPayment: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return nil, errors.New("payment_id must not be empty")
	}
	const q = `
	SELECT id, amount, currency, status, provider, created_at, metadata
	FROM payments WHERE id = $1
	`
	var p PaymentResult
	var meta string
	err := s.pool.QueryRow(ctx, q, paymentID).Scan(&p.PaymentID, &p.Amount, &p.Currency, &p.Status, &p.Provider, &p.CreatedAt, &meta)
	if err != nil {
		logger.LogError("GetPayment: failed to get payment", logger.ErrorField(err))
		return nil, errors.New("failed to get payment")
	}
	_ = json.Unmarshal([]byte(meta), &p.Raw)
	return &p, nil
}

func (s *Store) SetTenantProviderSecret(ctx context.Context, tenantID, provider string, config map[string]string) error {
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
	_, err = s.pool.Exec(ctx, q, tenantID, provider, string(cfgJSON))
	if err != nil {
		logger.LogError("SetTenantProviderSecret: failed to upsert secret", logger.ErrorField(err))
		return errors.New("failed to upsert tenant provider secret")
	}
	return nil
}

func (s *Store) GetTenantProviderSecret(ctx context.Context, tenantID, provider string) (map[string]string, error) {
	if tenantID == "" || provider == "" {
		logger.LogError("GetTenantProviderSecret: tenant_id and provider required", logger.ErrorField(errors.New("tenant_id and provider required")))
		return nil, errors.New("tenant_id and provider required")
	}
	const q = `
	SELECT config_json FROM tenant_provider_secret WHERE tenant_id = $1 AND provider = $2
	`
	var cfgJSON string
	err := s.pool.QueryRow(ctx, q, tenantID, provider).Scan(&cfgJSON)
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
func (s *Store) ListFailedPayments(ctx context.Context, tenantID string) ([]*FailedPayment, error) {
	if tenantID == "" {
		logger.LogError("ListFailedPayments: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	const q = `
	SELECT id, invoice_id, dunning_attempts, dunning_state, last_dunning_attempt
	FROM payments
	WHERE tenant_id = $1 AND status = 'failed' AND dunning_state != 'recovered'
	`
	rows, err := s.pool.Query(ctx, q, tenantID)
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
func (s *Store) GetDunningConfig(ctx context.Context, tenantID string) (*DunningConfig, error) {
	if tenantID == "" {
		logger.LogError("GetDunningConfig: tenant_id must not be empty", logger.ErrorField(errors.New("tenant_id must not be empty")))
		return nil, errors.New("tenant_id must not be empty")
	}
	const q = `
	SELECT max_attempts, retry_intervals_json FROM tenant_dunning_config WHERE tenant_id = $1
	`
	var maxAttempts int
	var retryIntervalsJSON string
	err := s.pool.QueryRow(ctx, q, tenantID).Scan(&maxAttempts, &retryIntervalsJSON)
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
func (s *Store) UpdateDunningState(ctx context.Context, paymentID, state string, attempts int) error {
	if paymentID == "" {
		logger.LogError("UpdateDunningState: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return errors.New("payment_id must not be empty")
	}
	const q = `
	UPDATE payments SET dunning_state = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3
	`
	_, err := s.pool.Exec(ctx, q, state, attempts, paymentID)
	if err != nil {
		logger.LogError("UpdateDunningState: update failed", logger.ErrorField(err))
		return errors.New("failed to update dunning state")
	}
	return nil
}

// UpdateDunningAttempt sets last_dunning_attempt and dunning_attempts for a payment
func (s *Store) UpdateDunningAttempt(ctx context.Context, paymentID string, lastAttempt time.Time, attempts int) error {
	if paymentID == "" {
		logger.LogError("UpdateDunningAttempt: payment_id must not be empty", logger.ErrorField(errors.New("payment_id must not be empty")))
		return errors.New("payment_id must not be empty")
	}
	const q = `
	UPDATE payments SET last_dunning_attempt = $1, dunning_attempts = $2, updated_at = NOW() WHERE id = $3
	`
	_, err := s.pool.Exec(ctx, q, lastAttempt, attempts, paymentID)
	if err != nil {
		logger.LogError("UpdateDunningAttempt: update failed", logger.ErrorField(err))
		return errors.New("failed to update dunning attempt")
	}
	return nil
}

// CreateDispute inserts a new dispute record
func (s *Store) CreateDispute(ctx context.Context, d *Dispute) error {
	if d == nil {
		logger.LogError("CreateDispute: dispute must not be nil", logger.ErrorField(errors.New("dispute must not be nil")))
		return errors.New("dispute must not be nil")
	}
	raw, _ := json.Marshal(d.Raw)
	const q = `
	INSERT INTO disputes (id, payment_id, tenant_id, provider, status, reason, amount, currency, evidence_due, evidence_submitted, created_at, updated_at, raw_json)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`
	_, err := s.pool.Exec(ctx, q, d.ID, d.PaymentID, d.TenantID, d.Provider, d.Status, d.Reason, d.Amount, d.Currency, d.EvidenceDue, d.EvidenceSubmitted, d.CreatedAt, d.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("CreateDispute: insert failed", logger.ErrorField(err))
		return errors.New("failed to create dispute")
	}
	return nil
}

// GetDispute fetches a dispute by ID
func (s *Store) GetDispute(ctx context.Context, disputeID string) (*Dispute, error) {
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
	err := s.pool.QueryRow(ctx, q, disputeID).Scan(&d.ID, &d.PaymentID, &d.TenantID, &d.Provider, &status, &d.Reason, &d.Amount, &d.Currency, &evidenceDue, &evidenceSubmitted, &d.CreatedAt, &d.UpdatedAt, &raw)
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
func (s *Store) ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error) {
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
	rows, err := s.pool.Query(ctx, q, args...)
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
func (s *Store) UpdateDisputeStatus(ctx context.Context, disputeID string, status DisputeStatus, evidenceSubmitted *time.Time) error {
	if disputeID == "" {
		logger.LogError("UpdateDisputeStatus: dispute_id must not be empty", logger.ErrorField(errors.New("dispute_id must not be empty")))
		return errors.New("dispute_id must not be empty")
	}
	const q = `UPDATE disputes SET status = $1, evidence_submitted = $2, updated_at = NOW() WHERE id = $3`
	_, err := s.pool.Exec(ctx, q, string(status), evidenceSubmitted, disputeID)
	if err != nil {
		logger.LogError("UpdateDisputeStatus: update failed", logger.ErrorField(err))
		return errors.New("failed to update dispute status")
	}
	return nil
}

// CreateDisputeEvidence inserts a new evidence record
func (s *Store) CreateDisputeEvidence(ctx context.Context, e *DisputeEvidence) error {
	if e == nil {
		logger.LogError("CreateDisputeEvidence: evidence must not be nil", logger.ErrorField(errors.New("evidence must not be nil")))
		return errors.New("evidence must not be nil")
	}
	raw, _ := json.Marshal(e.Raw)
	const q = `
	INSERT INTO dispute_evidence (id, dispute_id, tenant_id, file_url, file_name, file_type, uploaded_by, uploaded_at, provider_status, provider_response, created_at, updated_at, raw_json)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`
	_, err := s.pool.Exec(ctx, q, e.ID, e.DisputeID, e.TenantID, e.FileURL, e.FileName, e.FileType, e.UploadedBy, e.UploadedAt, e.ProviderStatus, e.ProviderResponse, e.CreatedAt, e.UpdatedAt, string(raw))
	if err != nil {
		logger.LogError("CreateDisputeEvidence: insert failed", logger.ErrorField(err))
		return errors.New("failed to create dispute evidence")
	}
	return nil
}

// GetDisputeEvidence fetches an evidence record by ID
func (s *Store) GetDisputeEvidence(ctx context.Context, evidenceID string) (*DisputeEvidence, error) {
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
	err := s.pool.QueryRow(ctx, q, evidenceID).Scan(&e.ID, &e.DisputeID, &e.TenantID, &e.FileURL, &e.FileName, &e.FileType, &e.UploadedBy, &e.UploadedAt, &e.ProviderStatus, &e.ProviderResponse, &e.CreatedAt, &e.UpdatedAt, &raw)
	if err != nil {
		logger.LogError("GetDisputeEvidence: query failed", logger.ErrorField(err))
		return nil, errors.New("failed to get dispute evidence")
	}
	_ = json.Unmarshal([]byte(raw), &e.Raw)
	return &e, nil
}

// ListDisputeEvidence returns evidence for a dispute/tenant
func (s *Store) ListDisputeEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error) {
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
	rows, err := s.pool.Query(ctx, q, disputeID, tenantID, pageSize, (page-1)*pageSize)
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
func (s *Store) UpdateDisputeEvidenceStatus(ctx context.Context, evidenceID, providerStatus, providerResponse string) error {
	if evidenceID == "" {
		logger.LogError("UpdateDisputeEvidenceStatus: evidence_id must not be empty", logger.ErrorField(errors.New("evidence_id must not be empty")))
		return errors.New("evidence_id must not be empty")
	}
	const q = `UPDATE dispute_evidence SET provider_status = $1, provider_response = $2, updated_at = NOW() WHERE id = $3`
	_, err := s.pool.Exec(ctx, q, providerStatus, providerResponse, evidenceID)
	if err != nil {
		logger.LogError("UpdateDisputeEvidenceStatus: update failed", logger.ErrorField(err))
		return errors.New("failed to update dispute evidence status")
	}
	return nil
}
