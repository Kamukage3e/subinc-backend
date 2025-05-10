package billing_management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

func NewPostgresStore(db *pgxpool.Pool, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

// CreateAccount inserts a new account into the DB
func (s *PostgresStore) CreateAccount(ctx context.Context, a Account) (Account, error) {
	const q = `INSERT INTO accounts (id, tenant_id, email, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, a.ID, a.TenantID, a.Email, a.Status, a.CreatedAt, a.UpdatedAt)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return Account{}, err
	}
	return out, nil
}

// GetAccount fetches an account by ID
func (s *PostgresStore) GetAccount(ctx context.Context, id string) (Account, error) {
	const q = `SELECT id, tenant_id, email, status, created_at, updated_at FROM accounts WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			s.logger.Warn("GetAccount: not found", logger.String("id", id))
			return Account{}, errors.New("no rows")
		}
		s.logger.Error("GetAccount failed", logger.ErrorField(err), logger.String("id", id))
		return Account{}, err
	}
	return out, nil
}

// UpdateAccount updates an account in the DB
func (s *PostgresStore) UpdateAccount(ctx context.Context, a Account) (Account, error) {
	const q = `UPDATE accounts SET tenant_id = $2, email = $3, status = $4, updated_at = $5 WHERE id = $1 RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, a.ID, a.TenantID, a.Email, a.Status, a.UpdatedAt)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateAccount failed", logger.ErrorField(err), logger.Any("account", a))
		return Account{}, err
	}
	return out, nil
}

// ListAccounts returns a paginated list of accounts for a tenant
func (s *PostgresStore) ListAccounts(ctx context.Context, tenantID string, page, pageSize int) ([]Account, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, tenant_id, email, status, created_at, updated_at FROM accounts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListAccounts query failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Email, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			s.logger.Error("ListAccounts scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// --- Plan CRUD ---
func (s *PostgresStore) CreatePlan(ctx context.Context, p Plan) (Plan, error) {
	const q = `INSERT INTO plans (id, name, description, price, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, description, price, active, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, p.ID, p.Name, p.Description, p.Price, p.Active, p.CreatedAt, p.UpdatedAt)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreatePlan failed", logger.ErrorField(err), logger.Any("plan", p))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPlan(ctx context.Context, id string) (Plan, error) {
	const q = `SELECT id, name, description, price, active, created_at, updated_at FROM plans WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			s.logger.Warn("GetPlan: not found", logger.String("id", id))
			return Plan{}, errors.New("no rows")
		}
		s.logger.Error("GetPlan failed", logger.ErrorField(err), logger.String("id", id))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdatePlan(ctx context.Context, p Plan) (Plan, error) {
	const q = `UPDATE plans SET name = $2, description = $3, price = $4, active = $5, updated_at = $6 WHERE id = $1 RETURNING id, name, description, price, active, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, p.ID, p.Name, p.Description, p.Price, p.Active, p.UpdatedAt)
	var out Plan
	if err := row.Scan(&out.ID, &out.Name, &out.Description, &out.Price, &out.Active, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdatePlan failed", logger.ErrorField(err), logger.Any("plan", p))
		return Plan{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListPlans(ctx context.Context, activeOnly bool, page, pageSize int) ([]Plan, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, name, description, price, active, created_at, updated_at FROM plans`
	args := []interface{}{}
	if activeOnly {
		q += " WHERE active = true"
	}
	q += " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListPlans query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Active, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("ListPlans scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *PostgresStore) DeletePlan(ctx context.Context, id string) error {
	const q = `DELETE FROM plans WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	return err
}

// --- Usage CRUD ---
func (s *PostgresStore) CreateUsage(ctx context.Context, u Usage) (Usage, error) {
	const q = `INSERT INTO usage (id, account_id, metric, amount, period, created_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, account_id, metric, amount, period, created_at`
	row := s.db.QueryRow(ctx, q, u.ID, u.AccountID, u.Metric, u.Amount, u.Period, u.CreatedAt)
	var out Usage
	if err := row.Scan(&out.ID, &out.AccountID, &out.Metric, &out.Amount, &out.Period, &out.CreatedAt); err != nil {
		s.logger.Error("CreateUsage failed", logger.ErrorField(err), logger.Any("usage", u))
		return Usage{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListUsage(ctx context.Context, accountID, metric, period string, page, pageSize int) ([]Usage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, metric, amount, period, created_at FROM usage WHERE account_id = $1`
	args := []interface{}{accountID}
	if metric != "" {
		q += " AND metric = $2"
		args = append(args, metric)
	}
	if period != "" {
		q += " AND period = $3"
		args = append(args, period)
	}
	q += " ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListUsage query failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.ID, &u.AccountID, &u.Metric, &u.Amount, &u.Period, &u.CreatedAt); err != nil {
			s.logger.Error("ListUsage scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// --- Invoice CRUD ---
func (s *PostgresStore) CreateInvoice(ctx context.Context, i Invoice) (Invoice, error) {
	const q = `INSERT INTO invoices (id, account_id, amount, status, due_date, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, account_id, amount, status, due_date, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.CreatedAt, i.UpdatedAt)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateInvoice failed", logger.ErrorField(err), logger.Any("invoice", i))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetInvoice(ctx context.Context, id string) (Invoice, error) {
	const q = `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			s.logger.Warn("GetInvoice: not found", logger.String("id", id))
			return Invoice{}, errors.New("no rows")
		}
		s.logger.Error("GetInvoice failed", logger.ErrorField(err), logger.String("id", id))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateInvoice(ctx context.Context, i Invoice) (Invoice, error) {
	const q = `UPDATE invoices SET account_id = $2, amount = $3, status = $4, due_date = $5, updated_at = $6 WHERE id = $1 RETURNING id, account_id, amount, status, due_date, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.UpdatedAt)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateInvoice failed", logger.ErrorField(err), logger.Any("invoice", i))
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
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListInvoices query failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return nil, err
	}
	defer rows.Close()
	var out []Invoice
	for rows.Next() {
		var i Invoice
		if err := rows.Scan(&i.ID, &i.AccountID, &i.Amount, &i.Status, &i.DueDate, &i.CreatedAt, &i.UpdatedAt); err != nil {
			s.logger.Error("ListInvoices scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

func (s *PostgresStore) DeleteInvoice(ctx context.Context, id string) error {
	const q = `DELETE FROM invoices WHERE id = $1`
	_, err := s.db.Exec(ctx, q, id)
	return err
}

// --- Payment CRUD ---
func (s *PostgresStore) CreatePayment(ctx context.Context, p Payment) (Payment, error) {
	const q = `INSERT INTO payments (id, invoice_id, amount, status, method, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, invoice_id, amount, status, method, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, p.ID, p.InvoiceID, p.Amount, p.Status, p.Method, p.CreatedAt, p.UpdatedAt, p.Metadata)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Status, &out.Method, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("CreatePayment failed", logger.ErrorField(err), logger.Any("payment", p))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetPayment(ctx context.Context, id string) (Payment, error) {
	const q = `SELECT id, invoice_id, amount, status, method, created_at, updated_at, metadata FROM payments WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Status, &out.Method, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, errors.New("no rows")) {
			s.logger.Warn("GetPayment: not found", logger.String("id", id))
			return Payment{}, errors.New("no rows")
		}
		s.logger.Error("GetPayment failed", logger.ErrorField(err), logger.String("id", id))
		return Payment{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdatePayment(ctx context.Context, p Payment) (Payment, error) {
	const q = `UPDATE payments SET invoice_id = $2, amount = $3, status = $4, method = $5, updated_at = $6, metadata = $7 WHERE id = $1 RETURNING id, invoice_id, amount, status, method, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, p.ID, p.InvoiceID, p.Amount, p.Status, p.Method, p.UpdatedAt, p.Metadata)
	var out Payment
	if err := row.Scan(&out.ID, &out.InvoiceID, &out.Amount, &out.Status, &out.Method, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("UpdatePayment failed", logger.ErrorField(err), logger.Any("payment", p))
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
	const q = `SELECT id, invoice_id, amount, status, method, created_at, updated_at, metadata FROM payments WHERE invoice_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.Query(ctx, q, invoiceID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListPayments query failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return nil, err
	}
	defer rows.Close()
	var out []Payment
	for rows.Next() {
		var p Payment
		if err := rows.Scan(&p.ID, &p.InvoiceID, &p.Amount, &p.Status, &p.Method, &p.CreatedAt, &p.UpdatedAt, &p.Metadata); err != nil {
			s.logger.Error("ListPayments scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// --- Credit CRUD ---
func (s *PostgresStore) CreateCredit(ctx context.Context, c Credit) (Credit, error) {
	const q = `INSERT INTO credits (id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, c.ID, c.AccountID, c.InvoiceID, c.Amount, c.Currency, c.Type, c.Status, c.CreatedAt, c.UpdatedAt, c.Metadata)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("CreateCredit failed", logger.ErrorField(err), logger.Any("credit", c))
		return Credit{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetCredit(ctx context.Context, id string) (Credit, error) {
	const q = `SELECT id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata FROM credits WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("GetCredit: not found", logger.String("id", id))
			return Credit{}, sql.ErrNoRows
		}
		s.logger.Error("GetCredit failed", logger.ErrorField(err), logger.String("id", id))
		return Credit{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateCredit(ctx context.Context, c Credit) (Credit, error) {
	const q = `UPDATE credits SET account_id = $2, invoice_id = $3, amount = $4, currency = $5, type = $6, status = $7, updated_at = $8, metadata = $9 WHERE id = $1 RETURNING id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, c.ID, c.AccountID, c.InvoiceID, c.Amount, c.Currency, c.Type, c.Status, c.UpdatedAt, c.Metadata)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("UpdateCredit failed", logger.ErrorField(err), logger.Any("credit", c))
		return Credit{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListCredits(ctx context.Context, accountID, invoiceID, status string, page, pageSize int) ([]Credit, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, account_id, invoice_id, amount, currency, type, status, created_at, updated_at, metadata FROM credits WHERE 1=1`
	args := []interface{}{}
	if accountID != "" {
		q += " AND account_id = $1"
		args = append(args, accountID)
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
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListCredits query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Credit
	for rows.Next() {
		var c Credit
		if err := rows.Scan(&c.ID, &c.AccountID, &c.InvoiceID, &c.Amount, &c.Currency, &c.Type, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
			s.logger.Error("ListCredits scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// --- Refund CRUD ---
func (s *PostgresStore) CreateRefund(ctx context.Context, r Refund) (Refund, error) {
	const q = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, r.ID, r.PaymentID, r.InvoiceID, r.Amount, r.Currency, r.Status, r.Reason, r.CreatedAt, r.UpdatedAt, r.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Status, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("CreateRefund failed", logger.ErrorField(err), logger.Any("refund", r))
		return Refund{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetRefund(ctx context.Context, id string) (Refund, error) {
	const q = `SELECT id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata FROM refunds WHERE id = $1`
	row := s.db.QueryRow(ctx, q, id)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Status, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("GetRefund: not found", logger.String("id", id))
			return Refund{}, sql.ErrNoRows
		}
		s.logger.Error("GetRefund failed", logger.ErrorField(err), logger.String("id", id))
		return Refund{}, err
	}
	return out, nil
}

// --- AccountAction ---
func (s *PostgresStore) PerformAccountAction(ctx context.Context, accountID, action string, params map[string]interface{}) (map[string]interface{}, error) {
	if accountID == "" || action == "" {
		return nil, NewValidationError("account_id/action", "must not be empty")
	}
	var status string
	switch action {
	case "suspend":
		status = "suspended"
	case "activate":
		status = "active"
	case "close":
		status = "closed"
	default:
		// For custom actions, require explicit handler or reject
		return nil, NewValidationError("action", "unsupported account action")
	}
	const q = `UPDATE accounts SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING id, tenant_id, email, status, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, status, accountID)
	var out Account
	if err := row.Scan(&out.ID, &out.TenantID, &out.Email, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("PerformAccountAction: update failed", logger.ErrorField(err), logger.String("account_id", accountID), logger.String("action", action))
		return nil, err
	}
	return map[string]interface{}{
		"account": out,
		"action":  action,
		"status":  status,
	}, nil
}

// --- GetInvoicePreview ---
func (s *PostgresStore) GetInvoicePreview(ctx context.Context, accountID string) (Invoice, error) {
	if accountID == "" {
		return Invoice{}, NewValidationError("account_id", "must not be empty")
	}
	const q = `SELECT id, account_id, amount, status, due_date, created_at, updated_at FROM invoices WHERE account_id = $1 AND status = 'draft' ORDER BY created_at DESC LIMIT 1`
	row := s.db.QueryRow(ctx, q, accountID)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetInvoicePreview failed", logger.ErrorField(err), logger.String("account_id", accountID))
		return Invoice{}, err
	}
	return out, nil
}

// --- RedeemCoupon ---
func (s *PostgresStore) RedeemCoupon(ctx context.Context, code, accountID string) (Coupon, error) {
	if code == "" || accountID == "" {
		return Coupon{}, NewValidationError("code/account_id", "must not be empty")
	}
	// Check coupon validity
	const checkQ = `SELECT id, max_redemptions, redeemed, is_active, start_at, end_at FROM coupons WHERE code = $1`
	row := s.db.QueryRow(ctx, checkQ, code)
	var id string
	var maxRedemptions, redeemed int
	var isActive bool
	var startAt, endAt string
	if err := row.Scan(&id, &maxRedemptions, &redeemed, &isActive, &startAt, &endAt); err != nil {
		s.logger.Error("RedeemCoupon: not found", logger.ErrorField(err), logger.String("code", code))
		return Coupon{}, err
	}
	if !isActive {
		return Coupon{}, NewValidationError("coupon", "inactive coupon")
	}
	if maxRedemptions > 0 && redeemed >= maxRedemptions {
		return Coupon{}, NewValidationError("coupon", "max redemptions reached")
	}
	// Mark coupon as redeemed for account
	const q = `UPDATE coupons SET redeemed = redeemed + 1 WHERE code = $1 RETURNING id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata`
	row2 := s.db.QueryRow(ctx, q, code)
	var out Coupon
	if err := row2.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("RedeemCoupon failed", logger.ErrorField(err), logger.String("code", code))
		return Coupon{}, err
	}
	return out, nil
}

// --- ApplyCreditsToInvoice ---
func (s *PostgresStore) ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error {
	if invoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	q := `UPDATE invoices SET amount = amount - (SELECT COALESCE(SUM(amount),0) FROM credits WHERE invoice_id = $1 AND status = 'active'), updated_at = NOW() WHERE id = $1`
	_, err := s.db.Exec(ctx, q, invoiceID)
	return err
}

// --- GetBillingConfig / SetBillingConfig ---
func (s *PostgresStore) GetBillingConfig(ctx context.Context) (map[string]interface{}, error) {
	const q = `SELECT key, value FROM billing_config`
	rows, err := s.db.Query(ctx, q)
	if err != nil {
		s.logger.Error("GetBillingConfig query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	config := make(map[string]interface{})
	for rows.Next() {
		var key string
		var value interface{}
		if err := rows.Scan(&key, &value); err != nil {
			s.logger.Error("GetBillingConfig scan failed", logger.ErrorField(err))
			return nil, err
		}
		config[key] = value
	}
	return config, nil
}

func (s *PostgresStore) SetBillingConfig(ctx context.Context, input map[string]interface{}) error {
	for key, value := range input {
		q := `INSERT INTO billing_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`
		_, err := s.db.Exec(ctx, q, key, value)
		if err != nil {
			s.logger.Error("SetBillingConfig failed", logger.ErrorField(err), logger.String("key", key))
			return err
		}
	}
	return nil
}

// Implement WebhookSubscriptionService
func (s *PostgresStore) CreateWebhookSubscription(ctx context.Context, sub WebhookSubscription) (WebhookSubscription, error) {
	const q = `INSERT INTO webhook_subscriptions (id, tenant_id, url, event_types, secret, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, tenant_id, url, event_types, secret, status, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, sub.ID, sub.TenantID, sub.URL, strings.Join(sub.EventTypes, ","), sub.Secret, sub.Status, sub.CreatedAt, sub.UpdatedAt)
	var out WebhookSubscription
	var eventTypes string
	if err := row.Scan(&out.ID, &out.TenantID, &out.URL, &eventTypes, &out.Secret, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateWebhookSubscription failed", logger.ErrorField(err), logger.Any("sub", sub))
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
	rows, err := s.db.Query(ctx, q, tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("ListWebhookSubscriptions query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []WebhookSubscription
	for rows.Next() {
		var w WebhookSubscription
		var eventTypes string
		if err := rows.Scan(&w.ID, &w.TenantID, &w.URL, &eventTypes, &w.Secret, &w.Status, &w.CreatedAt, &w.UpdatedAt); err != nil {
			s.logger.Error("ListWebhookSubscriptions scan failed", logger.ErrorField(err))
			return nil, err
		}
		w.EventTypes = strings.Split(eventTypes, ",")
		out = append(out, w)
	}
	return out, nil
}

func (s *PostgresStore) DeleteWebhookSubscription(ctx context.Context, subID string) error {
	const q = `DELETE FROM webhook_subscriptions WHERE id = $1`
	_, err := s.db.Exec(ctx, q, subID)
	return err
}

// Implement TaxInfoService
func (s *PostgresStore) SetTaxInfo(ctx context.Context, info TaxInfo) (TaxInfo, error) {
	const q = `INSERT INTO tax_info (id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id) DO UPDATE SET country = $3, region = $4, tax_id = $5, tax_rate = $6, currency = $7, updated_at = $9 RETURNING id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at`
	row := s.db.QueryRow(ctx, q, info.ID, info.TenantID, info.Country, info.Region, info.TaxID, info.TaxRate, info.Currency, info.CreatedAt, info.UpdatedAt)
	var out TaxInfo
	if err := row.Scan(&out.ID, &out.TenantID, &out.Country, &out.Region, &out.TaxID, &out.TaxRate, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("SetTaxInfo failed", logger.ErrorField(err), logger.Any("info", info))
		return TaxInfo{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetTaxInfo(ctx context.Context, tenantID string) (TaxInfo, error) {
	const q = `SELECT id, tenant_id, country, region, tax_id, tax_rate, currency, created_at, updated_at FROM tax_info WHERE tenant_id = $1`
	row := s.db.QueryRow(ctx, q, tenantID)
	var out TaxInfo
	if err := row.Scan(&out.ID, &out.TenantID, &out.Country, &out.Region, &out.TaxID, &out.TaxRate, &out.Currency, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetTaxInfo failed", logger.ErrorField(err), logger.String("tenant_id", tenantID))
		return TaxInfo{}, err
	}
	return out, nil
}

// --- Reporting ---
func (s *PostgresStore) GetRevenueReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.db.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '30 days'`)
	var revenue float64
	if err := row.Scan(&revenue); err != nil {
		s.logger.Error("GetRevenueReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"revenue": revenue}, nil
}

func (s *PostgresStore) GetARReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.db.QueryRow(ctx, `SELECT COALESCE(SUM(amount),0) FROM invoices WHERE status IN ('issued', 'overdue')`)
	var ar float64
	if err := row.Scan(&ar); err != nil {
		s.logger.Error("GetARReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"accounts_receivable": ar}, nil
}

func (s *PostgresStore) GetChurnReport(ctx context.Context) (map[string]interface{}, error) {
	row := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM subscriptions WHERE status = 'canceled' AND canceled_at >= NOW() - INTERVAL '30 days'`)
	var churn int
	if err := row.Scan(&churn); err != nil {
		s.logger.Error("GetChurnReport failed", logger.ErrorField(err))
		return nil, err
	}
	return map[string]interface{}{"churned_subscriptions": churn}, nil
}

// --- Usage Aggregation/Overage ---
func (s *PostgresStore) AggregateUsageForBillingCycle(ctx context.Context, accountID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" {
		return nil, NewValidationError("account_id", "must not be empty")
	}
	rows, err := s.db.Query(ctx, `SELECT metric, SUM(amount) FROM usage WHERE account_id = $1 AND created_at >= $2 AND created_at <= $3 GROUP BY metric`, accountID, periodStart, periodEnd)
	if err != nil {
		s.logger.Error("AggregateUsageForBillingCycle failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	usageTotals := make(map[string]float64)
	for rows.Next() {
		var metric string
		var total float64
		if err := rows.Scan(&metric, &total); err != nil {
			s.logger.Error("AggregateUsageForBillingCycle scan failed", logger.ErrorField(err))
			return nil, err
		}
		usageTotals[metric] = total
	}
	return usageTotals, nil
}

func (s *PostgresStore) CalculateOverageCharges(ctx context.Context, accountID, planID string, periodStart, periodEnd time.Time) (map[string]float64, error) {
	if accountID == "" || planID == "" {
		return nil, NewValidationError("overage", "accountID and planID required")
	}
	plan, err := s.GetPlan(ctx, planID)
	if err != nil {
		s.logger.Error("CalculateOverageCharges: GetPlan failed", logger.ErrorField(err))
		return nil, err
	}
	usageTotals, err := s.AggregateUsageForBillingCycle(ctx, accountID, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	limits, overages, err := parsePlanPricing(plan.Pricing)
	if err != nil {
		return nil, err
	}
	overageCharges := make(map[string]float64)
	for resource, used := range usageTotals {
		limit := limits[resource]
		rate := overages[resource]
		if used > limit && rate > 0 {
			overageCharges[resource] = (used - limit) * rate
		}
	}
	return overageCharges, nil
}

// --- Plan Pricing Parsing ---
func parsePlanPricing(pricing string) (map[string]float64, map[string]float64, error) {
	var raw map[string]map[string]float64
	err := json.Unmarshal([]byte(pricing), &raw)
	if err != nil {
		return nil, nil, err
	}
	limits := make(map[string]float64)
	overages := make(map[string]float64)
	for k, v := range raw {
		limits[k] = v["limit"]
		overages[k] = v["overage"]
	}
	return limits, overages, nil
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
	row := s.db.QueryRow(ctx, q, i.ID, i.AccountID, i.Amount, i.Status, i.DueDate, i.CreatedAt, i.UpdatedAt, i.TaxAmount, i.TaxRate, i.Fees)
	var out Invoice
	if err := row.Scan(&out.ID, &out.AccountID, &out.Amount, &out.Status, &out.DueDate, &out.CreatedAt, &out.UpdatedAt, &out.TaxAmount, &out.TaxRate, &out.Fees); err != nil {
		s.logger.Error("CreateInvoiceWithFeesAndTax failed", logger.ErrorField(err), logger.Any("invoice", i))
		return Invoice{}, err
	}
	return out, nil
}

func (s *PostgresStore) CreateManualRefund(ctx context.Context, refund Refund) (Refund, error) {
	const q = `INSERT INTO refunds (id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, payment_id, invoice_id, amount, currency, status, reason, created_at, updated_at, metadata`
	row := s.db.QueryRow(ctx, q, refund.ID, refund.PaymentID, refund.InvoiceID, refund.Amount, refund.Currency, refund.Status, refund.Reason, refund.CreatedAt, refund.UpdatedAt, refund.Metadata)
	var out Refund
	if err := row.Scan(&out.ID, &out.PaymentID, &out.InvoiceID, &out.Amount, &out.Currency, &out.Status, &out.Reason, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		s.logger.Error("CreateManualRefund failed", logger.ErrorField(err), logger.Any("refund", refund))
		return Refund{}, err
	}
	return out, nil
}
