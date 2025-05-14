package discount

import "context"

// DiscountService defines all discount CRUD and lookup operations for SaaS billing.
// All methods must be implemented by a persistent store and be concurrency-safe.
type DiscountService interface {
	// CreateDiscount creates a new discount. Returns the created discount or error.
	CreateDiscount(input Discount) (Discount, error)
	// UpdateDiscount updates an existing discount. Returns the updated discount or error.
	UpdateDiscount(input Discount) (Discount, error)
	// DeleteDiscount deletes a discount by ID. Returns error if not found or in use.
	DeleteDiscount(id string) error
	// GetDiscount fetches a discount by ID. Returns error if not found.
	GetDiscount(id string) (Discount, error)
	// GetDiscountByCode fetches a discount by code. Returns error if not found.
	GetDiscountByCode(code string) (Discount, error)
	// ListDiscounts returns a paginated list of discounts. If activeOnly, only active discounts are returned.
	ListDiscounts(activeOnly bool, page, pageSize int) ([]Discount, error)
}

// CouponService defines all coupon CRUD, lookup, and redemption operations for SaaS billing.
// All methods must be implemented by a persistent store and be concurrency-safe.
type CouponService interface {
	// CreateCoupon creates a new coupon. Returns the created coupon or error.
	CreateCoupon(input Coupon) (Coupon, error)
	// UpdateCoupon updates an existing coupon. Returns the updated coupon or error.
	UpdateCoupon(input Coupon) (Coupon, error)
	// DeleteCoupon deletes a coupon by ID. Returns error if not found or in use.
	DeleteCoupon(id string) error
	// GetCoupon fetches a coupon by ID. Returns error if not found.
	GetCoupon(id string) (Coupon, error)
	// GetCouponByCode fetches a coupon by code. Returns error if not found.
	GetCouponByCode(code string) (Coupon, error)
	// ListCoupons returns a paginated list of coupons for a discount. If isActive is set, filters by active status.
	ListCoupons(discountID string, isActive *bool, page, pageSize int) ([]Coupon, error)
	// RedeemCoupon redeems a coupon for an account. Returns the updated coupon or error.
	RedeemCoupon(code, accountID string) (Coupon, error)
}

// CreditService defines all credit CRUD, lookup, and application operations for SaaS billing.
// All methods must be implemented by a persistent store and be concurrency-safe.
type CreditService interface {
	// CreateCredit creates a new credit. Returns the created credit or error.
	CreateCredit(input Credit) (Credit, error)
	// UpdateCredit updates an existing credit. Returns the updated credit or error.
	UpdateCredit(input Credit) (Credit, error)
	// PatchCredit applies an action (e.g. consume, expire) to a credit. Returns error if invalid.
	PatchCredit(id, action string, amount float64) error
	// DeleteCredit deletes a credit by ID. Returns error if not found or in use.
	DeleteCredit(id string) error
	// GetCredit fetches a credit by ID. Returns error if not found.
	GetCredit(id string) (Credit, error)
	// ListCredits returns a paginated list of credits for an account or invoice, filtered by status.
	ListCredits(accountID, invoiceID, status string, page, pageSize int) ([]Credit, error)
	// ApplyCreditsToInvoice applies all available credits to an invoice. Returns error if not possible.
	ApplyCreditsToInvoice(invoiceID string) error
	// GetExchangeRate fetches the exchange rate for two currencies. Returns error if not found.
	GetExchangeRate(ctx context.Context, base, quote string) (ExchangeRate, error)
}
