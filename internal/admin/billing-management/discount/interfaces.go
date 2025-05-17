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

// DiscountPlugin defines a hot-pluggable interface for discount providers
// Each implementation can be dynamically loaded and configured at runtime
type DiscountPlugin interface {
	// Plugin identity
	Name() string    // Unique name for the discount plugin
	Version() string // Version in semver format

	// Core discount operations
	CalculateDiscount(ctx context.Context, invoice interface{}, account interface{}) (float64, error) // Calculate discount amount
	ValidateCode(ctx context.Context, code string, accountID string) (bool, error)                    // Validate discount code
	ApplyDiscount(ctx context.Context, discountID string, invoiceID string) (float64, error)          // Apply discount to invoice

	// Plugin lifecycle
	Initialize(config map[string]interface{}) error // Initialize plugin with configuration
	Capabilities() []string                         // Return supported features
}

// DiscountPluginRegistry manages discount plugins
type DiscountPluginRegistry struct {
	plugins map[string]DiscountPlugin
}

// Global registry for discount plugins
var DiscountPlugins = &DiscountPluginRegistry{
	plugins: make(map[string]DiscountPlugin),
}

// Register adds a discount plugin to the registry
func (r *DiscountPluginRegistry) Register(plugin DiscountPlugin) {
	if plugin == nil {
		return
	}
	name := plugin.Name()
	if name == "" {
		return
	}
	r.plugins[name] = plugin
}

// Lookup retrieves a discount plugin by name
func (r *DiscountPluginRegistry) Lookup(name string) (DiscountPlugin, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered discount plugin names
func (r *DiscountPluginRegistry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Unregister removes a discount plugin from the registry
func (r *DiscountPluginRegistry) Unregister(name string) {
	delete(r.plugins, name)
}
