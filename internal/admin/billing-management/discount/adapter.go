package discount

import (
	"context"
)

type DiscountServiceAdapter struct {
	Store *PostgresStore
}

func (a *DiscountServiceAdapter) CreateDiscount(d Discount) (Discount, error) {
	return a.Store.CreateDiscount(context.Background(), d)
}
func (a *DiscountServiceAdapter) UpdateDiscount(d Discount) (Discount, error) {
	return a.Store.UpdateDiscount(context.Background(), d)
}
func (a *DiscountServiceAdapter) DeleteDiscount(id string) error {
	return a.Store.DeleteDiscount(context.Background(), id)
}
func (a *DiscountServiceAdapter) GetDiscount(id string) (Discount, error) {
	return a.Store.GetDiscount(context.Background(), id)
}
func (a *DiscountServiceAdapter) GetDiscountByCode(code string) (Discount, error) {
	return a.Store.GetDiscountByCode(context.Background(), code)
}
func (a *DiscountServiceAdapter) ListDiscounts(activeOnly bool, page, pageSize int) ([]Discount, error) {
	return a.Store.ListDiscounts(context.Background(), activeOnly, page, pageSize)
}

type CreditServiceAdapter struct {
	Store *PostgresStore
}

func (a *CreditServiceAdapter) CreateCredit(c Credit) (Credit, error) {
	return a.Store.CreateCredit(context.Background(), c)
}
func (a *CreditServiceAdapter) UpdateCredit(c Credit) (Credit, error) {
	return a.Store.UpdateCredit(context.Background(), c)
}
func (a *CreditServiceAdapter) PatchCredit(id, action string, amount float64) error {
	return a.Store.PatchCredit(context.Background(), id, action, amount)
}
func (a *CreditServiceAdapter) DeleteCredit(id string) error {
	return a.Store.DeleteCredit(context.Background(), id)
}
func (a *CreditServiceAdapter) GetCredit(id string) (Credit, error) {
	return a.Store.GetCredit(context.Background(), id)
}
func (a *CreditServiceAdapter) ListCredits(accountID, invoiceID, status string, page, pageSize int) ([]Credit, error) {
	return a.Store.ListCredits(context.Background(), accountID, invoiceID, status, page, pageSize)
}
func (a *CreditServiceAdapter) ApplyCreditsToInvoice(invoiceID string) error {
	return a.Store.ApplyCreditsToInvoice(context.Background(), invoiceID)
}
func (a *CreditServiceAdapter) GetExchangeRate(ctx context.Context, base, quote string) (ExchangeRate, error) {
	return a.Store.GetExchangeRate(ctx, base, quote)
}

type CouponServiceAdapter struct {
	Store *PostgresStore
}

func (a *CouponServiceAdapter) CreateCoupon(input Coupon) (Coupon, error) {
	return a.Store.CreateCoupon(context.Background(), input)
}
func (a *CouponServiceAdapter) UpdateCoupon(input Coupon) (Coupon, error) {
	return a.Store.UpdateCoupon(context.Background(), input)
}
func (a *CouponServiceAdapter) DeleteCoupon(id string) error {
	return a.Store.DeleteCoupon(context.Background(), id)
}
func (a *CouponServiceAdapter) GetCoupon(id string) (Coupon, error) {
	return a.Store.GetCoupon(context.Background(), id)
}
func (a *CouponServiceAdapter) GetCouponByCode(code string) (Coupon, error) {
	return a.Store.GetCouponByCode(context.Background(), code)
}
func (a *CouponServiceAdapter) ListCoupons(discountID string, isActive *bool, page, pageSize int) ([]Coupon, error) {
	return a.Store.ListCoupons(context.Background(), discountID, isActive, page, pageSize)
}
func (a *CouponServiceAdapter) RedeemCoupon(code, accountID string) (Coupon, error) {
	return a.Store.RedeemCoupon(context.Background(), code, accountID)
}
