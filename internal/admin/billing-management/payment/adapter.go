package payment

import (
	"context"
	"errors"
	"time"

	"github.com/subinc/subinc-backend/internal/pkg/logger"
	"github.com/subinc/subinc-backend/internal/pkg/plugin"
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
func (a *PaymentMethodServiceAdapter) UpdatePaymentMethod(ctx context.Context, input PaymentMethod) (PaymentMethod, error) {
	return a.Store.UpdatePaymentMethod(ctx, input)
}
func (a *PaymentMethodServiceAdapter) DeletePaymentMethod(ctx context.Context, id string) error {
	return a.Store.DeletePaymentMethod(ctx, id)
}
func (a *PaymentMethodServiceAdapter) GetPaymentMethod(ctx context.Context, id string) (PaymentMethod, error) {
	return a.Store.GetPaymentMethod(ctx, id)
}
func (a *PaymentMethodServiceAdapter) ListPaymentMethods(ctx context.Context, accountID, status string, page, pageSize int) ([]PaymentMethod, error) {
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

type TransactionServiceAdapter struct {
	Store *PostgresStore
}

func (a *TransactionServiceAdapter) GetTransactionReport(ctx context.Context, tenantID string, startDate time.Time, endDate time.Time, includeRefunds bool) (*TransactionReport, error) {
	return a.Store.GetTransactionReport(ctx, tenantID, startDate, endDate, includeRefunds)
}

func (a *TransactionServiceAdapter) GetPaymentMethodReport(ctx context.Context, tenantID string, startDate, endDate time.Time) (map[string]int, error) {
	return a.Store.GetPaymentMethodReport(ctx, tenantID, startDate, endDate)
}

func (a *TransactionServiceAdapter) GetTransactionVolume(ctx context.Context, tenantID string, startDate, endDate time.Time) (float64, int, error) {
	return a.Store.GetTransactionVolume(ctx, tenantID, startDate, endDate)
}

// PluginManagerAdapter adapts a plugin.Manager to implement the PluginService interface
// Centralized plugin management for payment plugins

type PluginManagerAdapter struct {
	Manager *plugin.Manager
	Store   StoreInterface
}

func (a *PluginManagerAdapter) ListPaymentPlugins(context.Context) ([]string, error) {
	if a.Manager == nil {
		logger.LogError("ListPaymentPlugins: plugin manager is nil")
		return []string{}, errors.New("plugin manager is nil")
	}
	return a.Manager.ListPlugins("payment"), nil
}

func (a *PluginManagerAdapter) GetPaymentPlugin(ctx context.Context, name string) (PaymentPlugin, error) {
	if a.Manager == nil {
		logger.LogError("GetPaymentPlugin: plugin manager is nil")
		return nil, errors.New("plugin manager is nil")
	}
	pluginObj, exists := a.Manager.GetPlugin("payment", name)
	if !exists {
		logger.LogError("GetPaymentPlugin: plugin not found", logger.String("plugin_name", name))
		return nil, errors.New("plugin not found")
	}
	paymentPlugin, ok := pluginObj.(PaymentPlugin)
	if !ok {
		logger.LogError("GetPaymentPlugin: invalid plugin type", logger.String("plugin_name", name))
		return nil, errors.New("invalid plugin type")
	}
	return paymentPlugin, nil
}

func (a *PluginManagerAdapter) SavePaymentPluginConfig(ctx context.Context, config *PaymentPluginConfig) error {
	if a.Store == nil {
		logger.LogError("SavePaymentPluginConfig: store not initialized")
		return errors.New("payment store not initialized")
	}
	return a.Store.SavePaymentPluginConfig(ctx, config)
}

func (a *PluginManagerAdapter) DisablePaymentPlugin(ctx context.Context, tenantID, pluginName string) error {
	if a.Store == nil {
		logger.LogError("DisablePaymentPlugin: store not initialized")
		return errors.New("payment store not initialized")
	}
	return a.Store.DisablePaymentPlugin(ctx, tenantID, pluginName)
}
