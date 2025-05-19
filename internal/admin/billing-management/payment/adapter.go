package payment

import (
	"context"
)

type PaymentServiceAdapter struct {
	Store *PostgresStore
}

func (a *PaymentServiceAdapter) CreatePayment(ctx context.Context, input Payment) (Payment, error) {
	return a.Store.CreatePayment(ctx, input)
}
func (a *PaymentServiceAdapter) UpdatePayment(ctx context.Context, input Payment) (Payment, error) {
	return a.Store.UpdatePayment(ctx, input)
}
func (a *PaymentServiceAdapter) GetPayment(ctx context.Context, id string) (Payment, error) {
	return a.Store.GetPayment(ctx, id)
}
func (a *PaymentServiceAdapter) ListPayments(ctx context.Context, invoiceID string, page, pageSize int) ([]Payment, error) {
	return a.Store.ListPayments(ctx, invoiceID, page, pageSize)
}
func (a *PaymentServiceAdapter) GetPaymentByIdempotencyKey(ctx context.Context, idempotencyKey string) (Payment, error) {
	return a.Store.GetPaymentByIdempotencyKey(ctx, idempotencyKey)
}
func (a *PaymentServiceAdapter) RefundPayment(ctx context.Context, req *RefundPaymentRequest) (*PaymentResult, error) {
	return a.Store.RefundPayment(ctx, req)
}
func (a *PaymentServiceAdapter) GetPaymentStatus(ctx context.Context, paymentID string) (*PaymentStatus, error) {
	return a.Store.GetPaymentStatus(ctx, paymentID)
}

type PaymentMethodServiceAdapter struct {
	Store *PostgresStore
}

// payment method
func (a *PaymentMethodServiceAdapter) CreatePaymentMethod(ctx context.Context, input PaymentMethod, data map[string]string) (PaymentMethod, error) {
	return a.Store.CreatePaymentMethod(ctx, input, data)
}
func (a *PaymentServiceAdapter) UpdatePaymentMethod(ctx context.Context, input PaymentMethod) (PaymentMethod, error) {
	return a.Store.UpdatePaymentMethod(ctx, input)
}
func (a *PaymentServiceAdapter) DeletePaymentMethod(ctx context.Context, id string) error {
	return a.Store.DeletePaymentMethod(ctx, id)
}
func (a *PaymentServiceAdapter) GetPaymentMethod(ctx context.Context, id string) (PaymentMethod, error) {
	return a.Store.GetPaymentMethod(ctx, id)
}
func (a *PaymentServiceAdapter) ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]PaymentMethod, error) {
	return a.Store.ListPaymentMethods(ctx, accountID, status, page, pageSize)
}

func (a *PaymentMethodServiceAdapter) PatchPaymentMethod(ctx context.Context, id string, setDefault *bool, status string) error {
	return a.Store.PatchPaymentMethod(ctx, id, setDefault, status)
}

// refund

type RefundServiceAdapter struct {
	Store *PostgresStore
}

func (a *RefundServiceAdapter) CreateRefund(ctx context.Context, input Refund) (Refund, error) {
	return a.Store.CreateRefund(ctx, input)
}
func (a *RefundServiceAdapter) UpdateRefund(ctx context.Context, input Refund) (Refund, error) {
	return a.Store.UpdateRefund(ctx, input)
}
func (a *RefundServiceAdapter) DeleteRefund(ctx context.Context, id string) error {
	return a.Store.DeleteRefund(ctx, id)
}
func (a *RefundServiceAdapter) GetRefund(ctx context.Context, id string) (Refund, error) {
	return a.Store.GetRefund(ctx, id)
}
func (a *RefundServiceAdapter) ListRefunds(ctx context.Context, paymentID, invoiceID, status string, page, pageSize int) ([]Refund, error) {
	return a.Store.ListRefunds(ctx, paymentID, invoiceID, status, page, pageSize)
}

type ManualRefundServiceAdapter struct {
	Store *PostgresStore
}

func (a *ManualRefundServiceAdapter) CreateManualRefund(ctx context.Context, input Refund) (Refund, error) {
	return a.Store.CreateManualRefund(ctx, input)
}

type DisputeServiceAdapter struct {
	Store *PostgresStore
}

func (a *DisputeServiceAdapter) CreateDispute(ctx context.Context, input *Dispute) error {
	return a.Store.CreateDispute(ctx, input)
}
func (a *DisputeServiceAdapter) UpdateDispute(ctx context.Context, input Dispute) (Dispute, error) {
	return a.Store.UpdateDispute(ctx, input)
}
func (a *DisputeServiceAdapter) DeleteDispute(ctx context.Context, id string) error {
	return a.Store.DeleteDispute(ctx, id)
}
func (a *DisputeServiceAdapter) GetDispute(ctx context.Context, id string) (*Dispute, error) {
	return a.Store.GetDispute(ctx, id)
}
func (a *DisputeServiceAdapter) ListDisputes(ctx context.Context, tenantID, paymentID string, status DisputeStatus, page, pageSize int) ([]*Dispute, error) {
	return a.Store.ListDisputes(ctx, tenantID, paymentID, status, page, pageSize)
}

type EvidenceServiceAdapter struct {
	Store *PostgresStore
}

func (a *EvidenceServiceAdapter) CreateEvidence(ctx context.Context, input *DisputeEvidence) error {
	return a.Store.CreateEvidence(ctx, input)
}
func (a *EvidenceServiceAdapter) UpdateEvidence(ctx context.Context, input *DisputeEvidence) error {
	return a.Store.UpdateEvidence(ctx, input)
}
func (a *EvidenceServiceAdapter) DeleteEvidence(ctx context.Context, id string) error {
	return a.Store.DeleteEvidence(ctx, id)
}
func (a *EvidenceServiceAdapter) ListEvidence(ctx context.Context, disputeID, tenantID string, page, pageSize int) ([]*DisputeEvidence, error) {
	return a.Store.ListEvidence(ctx, disputeID, tenantID, page, pageSize)
}
func (a *EvidenceServiceAdapter) GetEvidence(ctx context.Context, id string) (*DisputeEvidence, error) {
	return a.Store.GetEvidence(ctx, id)
}
