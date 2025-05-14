package discount

import (
	"context"
	"database/sql"
	"errors"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

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

// --- Credit CRUD ---
func (s *PostgresStore) CreateCredit(ctx context.Context, c Credit) (Credit, error) {
	const q = `INSERT INTO credits (id, account_id, invoice_id, amount, currency, original_amount, original_currency, type, status, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, account_id, invoice_id, amount, currency, original_amount, original_currency, type, status, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, c.ID, c.AccountID, c.InvoiceID, c.Amount, c.Currency, c.OriginalAmount, c.OriginalCurrency, c.Type, c.Status, c.CreatedAt, c.UpdatedAt, c.Metadata)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateCredit failed", logger.ErrorField(err), logger.Any("credit", c))
		return Credit{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetCredit(ctx context.Context, id string) (Credit, error) {
	const q = `SELECT id, account_id, invoice_id, amount, currency, original_amount, original_currency, type, status, created_at, updated_at, metadata FROM credits WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetCredit: not found", logger.String("id", id))
			return Credit{}, sql.ErrNoRows
		}
		logger.LogError("GetCredit failed", logger.ErrorField(err), logger.String("id", id))
		return Credit{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateCredit(ctx context.Context, c Credit) (Credit, error) {
	const q = `UPDATE credits SET account_id = $2, invoice_id = $3, amount = $4, currency = $5, original_amount = $6, original_currency = $7, type = $8, status = $9, updated_at = $10, metadata = $11 WHERE id = $1
		RETURNING id, account_id, invoice_id, amount, currency, original_amount, original_currency, type, status, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, c.ID, c.AccountID, c.InvoiceID, c.Amount, c.Currency, c.OriginalAmount, c.OriginalCurrency, c.Type, c.Status, c.UpdatedAt, c.Metadata)
	var out Credit
	if err := row.Scan(&out.ID, &out.AccountID, &out.InvoiceID, &out.Amount, &out.Currency, &out.OriginalAmount, &out.OriginalCurrency, &out.Type, &out.Status, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdateCredit failed", logger.ErrorField(err), logger.Any("credit", c))
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
	q := `SELECT id, account_id, invoice_id, amount, currency, original_amount, original_currency, type, status, created_at, updated_at, metadata FROM credits WHERE 1=1`
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
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListCredits query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Credit
	for rows.Next() {
		var c Credit
		if err := rows.Scan(&c.ID, &c.AccountID, &c.InvoiceID, &c.Amount, &c.Currency, &c.OriginalAmount, &c.OriginalCurrency, &c.Type, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
			logger.LogError("ListCredits scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, c)
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
	row := s.DB.QueryRow(ctx, checkQ, code)
	var id string
	var maxRedemptions, redeemed int
	var isActive bool
	var startAt, endAt string
	if err := row.Scan(&id, &maxRedemptions, &redeemed, &isActive, &startAt, &endAt); err != nil {
		logger.LogError("RedeemCoupon: not found", logger.ErrorField(err), logger.String("code", code))
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
	row2 := s.DB.QueryRow(ctx, q, code)
	var out Coupon
	if err := row2.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("RedeemCoupon failed", logger.ErrorField(err), logger.String("code", code))
		return Coupon{}, err
	}
	return out, nil
}

// --- Discount CRUD ---
func (s *PostgresStore) CreateDiscount(ctx context.Context, d Discount) (Discount, error) {
	const q = `INSERT INTO discounts (id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, d.ID, d.Code, d.Type, d.Value, d.MaxRedemptions, d.Redeemed, d.StartAt, d.EndAt, d.IsActive, d.CreatedAt, d.UpdatedAt, d.Metadata)
	var out Discount
	if err := row.Scan(&out.ID, &out.Code, &out.Type, &out.Value, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateDiscount failed", logger.ErrorField(err), logger.Any("discount", d))
		return Discount{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateDiscount(ctx context.Context, d Discount) (Discount, error) {
	const q = `UPDATE discounts SET code=$2, type=$3, value=$4, max_redemptions=$5, redeemed=$6, start_at=$7, end_at=$8, is_active=$9, updated_at=$10, metadata=$11 WHERE id=$1
		RETURNING id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, d.ID, d.Code, d.Type, d.Value, d.MaxRedemptions, d.Redeemed, d.StartAt, d.EndAt, d.IsActive, d.UpdatedAt, d.Metadata)
	var out Discount
	if err := row.Scan(&out.ID, &out.Code, &out.Type, &out.Value, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdateDiscount failed", logger.ErrorField(err), logger.Any("discount", d))
		return Discount{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteDiscount(ctx context.Context, id string) error {
	const q = `DELETE FROM discounts WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteDiscount failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) GetDiscount(ctx context.Context, id string) (Discount, error) {
	const q = `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Discount
	if err := row.Scan(&out.ID, &out.Code, &out.Type, &out.Value, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetDiscount: not found", logger.String("id", id))
			return Discount{}, sql.ErrNoRows
		}
		logger.LogError("GetDiscount failed", logger.ErrorField(err), logger.String("id", id))
		return Discount{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetDiscountByCode(ctx context.Context, code string) (Discount, error) {
	const q = `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts WHERE code = $1`
	row := s.DB.QueryRow(ctx, q, code)
	var out Discount
	if err := row.Scan(&out.ID, &out.Code, &out.Type, &out.Value, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetDiscountByCode: not found", logger.String("code", code))
			return Discount{}, sql.ErrNoRows
		}
		logger.LogError("GetDiscountByCode failed", logger.ErrorField(err), logger.String("code", code))
		return Discount{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListDiscounts(ctx context.Context, activeOnly bool, page, pageSize int) ([]Discount, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, code, type, value, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM discounts WHERE 1=1`
	args := []interface{}{}
	if activeOnly {
		q += " AND is_active = $1"
		args = append(args, true)
	}
	q += " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListDiscounts query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Discount
	for rows.Next() {
		var d Discount
		if err := rows.Scan(&d.ID, &d.Code, &d.Type, &d.Value, &d.MaxRedemptions, &d.Redeemed, &d.StartAt, &d.EndAt, &d.IsActive, &d.CreatedAt, &d.UpdatedAt, &d.Metadata); err != nil {
			logger.LogError("ListDiscounts scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// --- Coupon CRUD ---
func (s *PostgresStore) CreateCoupon(ctx context.Context, c Coupon) (Coupon, error) {
	const q = `INSERT INTO coupons (id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, c.ID, c.Code, c.DiscountID, c.MaxRedemptions, c.Redeemed, c.StartAt, c.EndAt, c.IsActive, c.CreatedAt, c.UpdatedAt, c.Metadata)
	var out Coupon
	if err := row.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("CreateCoupon failed", logger.ErrorField(err), logger.Any("coupon", c))
		return Coupon{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateCoupon(ctx context.Context, c Coupon) (Coupon, error) {
	const q = `UPDATE coupons SET code=$2, discount_id=$3, max_redemptions=$4, redeemed=$5, start_at=$6, end_at=$7, is_active=$8, updated_at=$9, metadata=$10 WHERE id=$1
		RETURNING id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata`
	row := s.DB.QueryRow(ctx, q, c.ID, c.Code, c.DiscountID, c.MaxRedemptions, c.Redeemed, c.StartAt, c.EndAt, c.IsActive, c.UpdatedAt, c.Metadata)
	var out Coupon
	if err := row.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		logger.LogError("UpdateCoupon failed", logger.ErrorField(err), logger.Any("coupon", c))
		return Coupon{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteCoupon(ctx context.Context, id string) error {
	const q = `DELETE FROM coupons WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteCoupon failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) GetCoupon(ctx context.Context, id string) (Coupon, error) {
	const q = `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons WHERE id = $1`
	row := s.DB.QueryRow(ctx, q, id)
	var out Coupon
	if err := row.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetCoupon: not found", logger.String("id", id))
			return Coupon{}, sql.ErrNoRows
		}
		logger.LogError("GetCoupon failed", logger.ErrorField(err), logger.String("id", id))
		return Coupon{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetCouponByCode(ctx context.Context, code string) (Coupon, error) {
	const q = `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons WHERE code = $1`
	row := s.DB.QueryRow(ctx, q, code)
	var out Coupon
	if err := row.Scan(&out.ID, &out.Code, &out.DiscountID, &out.MaxRedemptions, &out.Redeemed, &out.StartAt, &out.EndAt, &out.IsActive, &out.CreatedAt, &out.UpdatedAt, &out.Metadata); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.LogWarn("GetCouponByCode: not found", logger.String("code", code))
			return Coupon{}, sql.ErrNoRows
		}
		logger.LogError("GetCouponByCode failed", logger.ErrorField(err), logger.String("code", code))
		return Coupon{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListCoupons(ctx context.Context, discountID string, isActive *bool, page, pageSize int) ([]Coupon, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, code, discount_id, max_redemptions, redeemed, start_at, end_at, is_active, created_at, updated_at, metadata FROM coupons WHERE 1=1`
	args := []interface{}{}
	if discountID != "" {
		q += " AND discount_id = $1"
		args = append(args, discountID)
	}
	if isActive != nil {
		q += " AND is_active = $2"
		args = append(args, *isActive)
	}
	q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		logger.LogError("ListCoupons query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []Coupon
	for rows.Next() {
		var c Coupon
		if err := rows.Scan(&c.ID, &c.Code, &c.DiscountID, &c.MaxRedemptions, &c.Redeemed, &c.StartAt, &c.EndAt, &c.IsActive, &c.CreatedAt, &c.UpdatedAt, &c.Metadata); err != nil {
			logger.LogError("ListCoupons scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// PatchCredit applies an action (e.g. consume, expire) to a credit. Only supports 'consume' and 'expire'.
func (s *PostgresStore) PatchCredit(ctx context.Context, id, action string, amount float64) error {
	if id == "" || action == "" {
		return NewValidationError("id/action", "must not be empty")
	}
	switch action {
	case "consume":
		const q = `UPDATE credits SET amount = amount - $2, status = $3, updated_at = NOW() WHERE id = $1 AND status = $4 AND amount >= $2`
		res, err := s.DB.Exec(ctx, q, id, amount, CreditStatusConsumed, CreditStatusActive)
		if err != nil {
			logger.LogError("PatchCredit: consume failed", logger.ErrorField(err), logger.String("id", id))
			return err
		}
		if res.RowsAffected() == 0 {
			return NewValidationError("credit", "not enough balance or not active")
		}
		return nil
	case "expire":
		const q = `UPDATE credits SET status = $2, updated_at = NOW() WHERE id = $1 AND status = $3`
		res, err := s.DB.Exec(ctx, q, id, CreditStatusExpired, CreditStatusActive)
		if err != nil {
			logger.LogError("PatchCredit: expire failed", logger.ErrorField(err), logger.String("id", id))
			return err
		}
		if res.RowsAffected() == 0 {
			return NewValidationError("credit", "not active or not found")
		}
		return nil
	default:
		return NewValidationError("action", "unsupported action")
	}
}

func (s *PostgresStore) DeleteCredit(ctx context.Context, id string) error {
	const q = `DELETE FROM credits WHERE id = $1`
	_, err := s.DB.Exec(ctx, q, id)
	if err != nil {
		logger.LogError("DeleteCredit failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

// ApplyCreditsToInvoice applies all available credits to an invoice. Consumes credits in FIFO order until invoice is paid or credits exhausted.
func (s *PostgresStore) ApplyCreditsToInvoice(ctx context.Context, invoiceID string) error {
	if invoiceID == "" {
		return NewValidationError("invoice_id", "must not be empty")
	}
	// Get all active credits for this invoice
	const q = `SELECT id, amount FROM credits WHERE invoice_id = $1 AND status = $2 ORDER BY created_at ASC`
	rows, err := s.DB.Query(ctx, q, invoiceID, CreditStatusActive)
	if err != nil {
		logger.LogError("ApplyCreditsToInvoice: query failed", logger.ErrorField(err), logger.String("invoice_id", invoiceID))
		return err
	}
	defer rows.Close()
	var credits []struct {
		id     string
		amount float64
	}
	for rows.Next() {
		var id string
		var amount float64
		if err := rows.Scan(&id, &amount); err != nil {
			logger.LogError("ApplyCreditsToInvoice: scan failed", logger.ErrorField(err))
			return err
		}
		credits = append(credits, struct {
			id     string
			amount float64
		}{id, amount})
	}
	if len(credits) == 0 {
		return NewValidationError("credits", "no active credits for invoice")
	}
	// Mark all as consumed
	for _, c := range credits {
		const uq = `UPDATE credits SET status = $2, updated_at = NOW() WHERE id = $1 AND status = $3`
		_, err := s.DB.Exec(ctx, uq, c.id, CreditStatusConsumed, CreditStatusActive)
		if err != nil {
			logger.LogError("ApplyCreditsToInvoice: update failed", logger.ErrorField(err), logger.String("id", c.id))
			return err
		}
	}
	return nil
}
